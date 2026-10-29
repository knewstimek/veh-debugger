#include "mcp_server.h"
#include "tools_common.h"
#include <algorithm>
#include <cctype>
#include <map>

namespace veh {
namespace {
uint64_t HexValue(const std::string& text) {
    if (text.size() < 3 || text.rfind("0x", 0) != 0 || text.find_first_not_of("0123456789abcdefABCDEF", 2) != std::string::npos)
        throw AnalysisError("analysis_address", "Expected a 0x-prefixed address");
    try { return std::stoull(text.substr(2), nullptr, 16); }
    catch (...) { throw AnalysisError("analysis_address", "Address overflow"); }
}
std::string Bytes(std::string text) {
    text.erase(std::remove(text.begin(), text.end(), ' '), text.end());
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    if (text.empty() || text.size() > 30 || text.size() % 2 || text.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw AnalysisError("analysis_code", "Instruction bytes are unavailable");
    return text;
}
json Preview(const json& entry) {
    json out;
    for (const char* key : {"id", "module", "rva", "label", "status", "author", "position", "revision", "persistent_identity"})
        if (entry.contains(key)) out[key] = entry[key];
    const auto comment = entry.value("comment", "");
    out["comment"] = comment.substr(0, 240);
    // UTF-8 prefixes must not end inside a multibyte character.
    if (comment.size() > 240) {
        size_t end = 240;
        while (end && (static_cast<unsigned char>(comment[end]) & 0xc0) == 0x80) --end;
        out["comment"] = comment.substr(0, end); out["comment_truncated"] = true;
    }
    out["evidence_count"] = entry.at("evidence").size();
    if (out.dump().size() > 1024) {
        out["comment"] = ""; out["comment_truncated"] = true;
        out.erase("author"); out.erase("module");
        if (out.dump().size() > 1024) { out["label"] = ""; out["preview_truncated"] = true; }
    }
    return out;
}
void Text(const json& args, const char* field, size_t maximum) {
    if (args.contains(field) && (!args[field].is_string() || args[field].get_ref<const std::string&>().size() > maximum ||
            args[field].get_ref<const std::string&>().find('\0') != std::string::npos))
        throw AnalysisError("analysis_arguments", std::string(field) + " must be a bounded string");
}
json Detail(json entry, const json& args) {
    if (args.contains("history_limit") && (!args["history_limit"].is_number_integer() || args["history_limit"] < 0 || args["history_limit"] > 8))
        throw AnalysisError("analysis_arguments", "history_limit must be 0-8");
    auto history = entry.value("history", json::array()); entry.erase("history"); entry["history_count"] = history.size();
    const auto limit = args.value("history_limit", 0);
    if (limit && !history.empty()) {
        while (history.size() > static_cast<size_t>(limit)) history.erase(history.begin());
        entry["history"] = std::move(history);
    }
    return entry;
}
json CompactMutation(json result) {
    if (result.contains("annotation")) {
        const auto& entry = result["annotation"]; auto preview = Preview(entry);
        preview["build_id"] = entry["build_id"]; preview["original_bytes"] = entry["original_bytes"];
        preview["history_count"] = entry.value("history_count", size_t{0}); result["annotation"] = std::move(preview);
    }
    return result;
}
void ApplyFields(json& entry, const json& args) {
    for (const auto& field : std::vector<std::pair<const char*, size_t>>{{"comment",4096},{"label",128},{"status",32},{"author",64},{"position",16},{"context",512}}) {
        Text(args, field.first, field.second); if (args.contains(field.first)) entry[field.first] = args[field.first];
    }
    if (entry["status"] != "hypothesis" && entry["status"] != "observed" && entry["status"] != "refuted")
        throw AnalysisError("analysis_arguments", "status must be hypothesis, observed or refuted (observed is not a universal proof)");
    if (entry["position"] != "before" && entry["position"] != "after") throw AnalysisError("analysis_arguments", "position must be before or after");
    if (entry["label"] == "" && entry["comment"] == "") throw AnalysisError("analysis_arguments", "A label or comment is required");
    if (args.contains("evidence")) entry["evidence"] = args["evidence"];
    if (!entry["evidence"].is_array() || entry["evidence"].size() > 16) throw AnalysisError("analysis_arguments", "evidence must be at most 16 short references");
    for (const auto& evidence : entry["evidence"]) if (!evidence.is_string() || evidence.get_ref<const std::string&>().size() > 512 ||
            evidence.get_ref<const std::string&>().find('\0') != std::string::npos)
        throw AnalysisError("analysis_arguments", "Evidence references must be strings of at most 512 bytes");
}
}

json McpServer::AnnotationContext(uint64_t address, const std::vector<ModuleEntry>& modules) {
    const ModuleEntry* selected = nullptr;
    for (const auto& module : modules) if (address >= module.baseAddress && address - module.baseAddress < module.size) {
        if (selected && selected->baseAddress != module.baseAddress)
            throw AnalysisError("analysis_module", "Address belongs to overlapping module ranges");
        selected = &module;
    }
    if (!selected) throw AnalysisError("analysis_module", "Annotations currently require a listed image module");
    GetModuleIdentityResponse identity{}; std::string error;
    const bool stable = session_.GetModuleIdentity(selected->baseAddress, identity, error);
    if (stable && (identity.imageSize != selected->size || (selected->addressBits && selected->addressBits != identity.addressBits)))
        throw AnalysisError("analysis_identity", "Module identity does not match the current module list");
    std::string build;
    if (stable) {
        const char* hex = "0123456789abcdef"; build = "sha256:";
        for (auto value : identity.sha256) { build += hex[value >> 4]; build += hex[value & 15]; }
        build += ":" + std::to_string(identity.addressBits);
    } else build = "session:" + annotationSession_ + ":" + std::to_string(session_.GetSessionGeneration()) + ":" + HexAddr(selected->baseAddress);
    json out = {{"build_id", build}, {"module", selected->name}, {"module_base", HexAddr(selected->baseAddress)},
        {"address_bits", stable ? identity.addressBits : selected->addressBits}, {"persistent_identity", stable}};
    if (stable) out["module_epoch"] = std::to_string(identity.moduleEpoch);
    if (!stable) out["identity_warning"] = error;
    return out;
}

json McpServer::ToolAnalysis(const json& args) {
    try {
        if (!args.is_object()) throw AnalysisError("analysis_arguments", "analysis must be an object");
        const auto operation = args.value("operation", "status");
        if (operation == "status") return analysisStore_.Status();
        if (operation == "open") {
            Text(args, "directory", 32768);
            return analysisStore_.Open(args.value("directory", ""), JsonBool(args, "create", false));
        }
        if (operation == "close") return analysisStore_.Close();
        const auto doc = analysisStore_.Snapshot();
        if (doc.is_null()) throw AnalysisError("analysis_not_open", "Open an analysis directory first");
        if (operation == "list" || operation == "search") {
            Text(args, "query", 256); Text(args, "module", 256); Text(args, "build_id", 256);
            if (args.contains("limit") && (!args["limit"].is_number_integer() || args["limit"] < 1 || args["limit"] > 100))
                throw AnalysisError("analysis_arguments", "limit must be 1-100");
            if (args.contains("offset") && (!args["offset"].is_number_integer() || args["offset"] < 0 || args["offset"] > 4096))
                throw AnalysisError("analysis_arguments", "offset must be 0-4096");
            const auto limit = args.value("limit", 20), offset = args.value("offset", 0);
            const auto query = args.value("query", ""), module = args.value("module", ""), build = args.value("build_id", "");
            json found = json::array(); size_t matched = 0;
            for (const auto& entry : doc["entries"]) {
                if ((!module.empty() && _stricmp(module.c_str(), entry["module"].get_ref<const std::string&>().c_str())) ||
                        (!build.empty() && entry["build_id"] != build) ||
                        (!query.empty() && entry.value("comment", "").find(query) == std::string::npos && entry.value("label", "").find(query) == std::string::npos)) continue;
                if (matched++ < static_cast<size_t>(offset)) continue;
                if (found.size() < static_cast<size_t>(limit)) found.push_back(Preview(entry));
            }
            return {{"annotations", found}, {"count", found.size()}, {"total", matched},
                {"next_offset", matched > offset + found.size() ? json(offset + found.size()) : json(nullptr)}, {"revision", doc["revision"]}};
        }
        if (operation != "get" && operation != "set" && operation != "delete")
            throw AnalysisError("analysis_arguments", "Unknown analysis operation");
        Text(args, "id", 256); Text(args, "expected_revision", 20);
        const auto expected = args.value("expected_revision", "");
        if (args.contains("id")) {
            const auto id = args["id"].get<std::string>();
            if (!doc["entries"].contains(id)) throw AnalysisError("analysis_missing", "Annotation not found");
            if (operation == "delete") return analysisStore_.Mutate(operation, {{"id", id}}, expected);
            if (operation == "set") {
                auto entry = doc["entries"][id];
                if (entry.value("persistent_identity", false)) throw AnalysisError("analysis_arguments", "Updating a build-bound annotation requires a current address");
                ApplyFields(entry, args); auto out = CompactMutation(analysisStore_.Mutate(operation, std::move(entry), expected));
                out["code_validation"] = "not_checked"; return out;
            }
            return {{"annotation", Detail(doc["entries"][id], args)}, {"code_validation", "not_checked"}};
        }
        if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
        GetModuleIdentityResponse epochBefore{}; std::string epochError;
        const bool hasEpoch = session_.GetModuleIdentity(0, epochBefore, epochError);
        Text(args, "address", 512);
        uint64_t address = 0;
        if (!ParseAddress(args.value("address", ""), address)) throw AnalysisError("analysis_address", "A current instruction address is required");
        std::string moduleError; const auto modules = session_.GetModules(&moduleError);
        if (!moduleError.empty()) throw AnalysisError("analysis_module", moduleError);
        auto context = AnnotationContext(address, modules);
        const auto stableObservation = [&] {
            if (!context["persistent_identity"].get<bool>()) return;
            GetModuleIdentityResponse after{}; std::string error;
            if (!hasEpoch || context.value("module_epoch", "") != std::to_string(epochBefore.moduleEpoch) ||
                    !session_.GetModuleIdentity(0, after, error) || after.moduleEpoch != epochBefore.moduleEpoch)
                throw AnalysisError("analysis_target_changed", "Target modules changed during inspection; no note was saved/applied. Retry the lookup");
        };
        if (!context["persistent_identity"].get<bool>() &&
                (operation == "delete" || (operation == "set" && !expected.empty())))
            throw AnalysisError("analysis_identity_unverified", "This backend cannot bind notes to a module lifetime; use the stored id and expected_revision to edit/delete the note");
        // Without a stable identity, address/base/bytes cannot distinguish an
        // unload/reload ABA. Save a distinct unbound note, never auto-apply it.
        if (operation == "set" && !context["persistent_identity"].get<bool>())
            context["build_id"] = context["build_id"].get<std::string>() + ":entry:" + AnalysisStore::Nonce();
        const auto rva = HexAddr(address - HexValue(context["module_base"].get<std::string>()));
        const auto id = context["build_id"].get<std::string>() + "@" + rva;
        const auto found = doc["entries"].find(id);
        if (operation == "delete") { stableObservation(); return analysisStore_.Mutate(operation, {{"id", id}}, expected); }
        const auto instructions = session_.Disassemble(address, 1);
        if (instructions.empty()) throw AnalysisError("analysis_code", "Cannot inspect current instruction bytes");
        const auto bytes = Bytes(instructions[0].bytes);
        stableObservation();
        if (operation == "get") {
            json out = {{"identity", context}, {"annotation", found == doc["entries"].end() ? json(nullptr) : Detail(*found, args)}};
            size_t previous = 0;
            for (const auto& entry : doc["entries"]) if (entry["module"] == context["module"] && entry["build_id"] != context["build_id"]) ++previous;
            out["previous_build_records"] = previous;
            if (found != doc["entries"].end()) out["stale"] = found->value("original_bytes", "") != bytes;
            return out;
        }
        json entry = found == doc["entries"].end() ? json{{"label", ""}, {"comment", ""}, {"status", "hypothesis"},
            {"author", "unspecified"}, {"position", "before"}, {"context", ""}, {"evidence", json::array()}} : *found;
        if (found != doc["entries"].end() && entry["original_bytes"] != bytes && !JsonBool(args, "accept_code_change", false))
            throw AnalysisError("analysis_code_changed", "Code changed; inspect the old entry and explicitly accept_code_change before updating");
        ApplyFields(entry, args);
        entry["id"] = id; entry["build_id"] = context["build_id"]; entry["persistent_identity"] = context["persistent_identity"];
        entry["module"] = context["module"]; entry["address_bits"] = context["address_bits"]; entry["rva"] = rva; entry["original_bytes"] = bytes;
        auto out = CompactMutation(analysisStore_.Mutate(operation, std::move(entry), expected)); out["identity"] = context; return out;
    } catch (const AnalysisError& error) { return {{"error", error.what()}, {"code", error.code}}; }
      catch (const std::exception& error) { return {{"error", error.what()}, {"code", "analysis_error"}}; }
}

std::string McpServer::AnnotationEpoch(bool labelsOnly) {
    try {
        const auto doc = analysisStore_.Snapshot();
        if (doc.is_null() || doc["entries"].empty()) return {};
        if (labelsOnly && std::none_of(doc["entries"].begin(), doc["entries"].end(),
                [](const json& entry) { return !entry.value("label", "").empty(); })) return {};
        GetModuleIdentityResponse epoch{}; std::string error;
        if (session_.GetModuleIdentity(0, epoch, error)) return std::to_string(epoch.moduleEpoch);
    } catch (...) {}
    return {};
}

void McpServer::AddAnnotations(json& output, bool codeAvailable, const std::string& beforeEpoch, bool labelsOnly) {
    auto rows = output; // Commit enrichment only after the complete observation is validated.
    if (rows.empty()) return;
    try {
        const auto doc = analysisStore_.Snapshot();
        if (doc.is_null() || doc["entries"].empty()) return;
        if (beforeEpoch.empty()) {
            output[0]["analysis_unbound_records"] = doc["entries"].size();
            output[0]["analysis_warning"] = "Build lifetime could not be verified; read stored notes by id. No notes were auto-applied";
            return;
        }
        std::string error; const auto modules = session_.GetModules(&error);
        if (!error.empty()) throw AnalysisError("analysis_module", error);
        std::map<uint64_t, json> contexts;
        std::set<uint64_t> reportedHistory;
        size_t previews = 0;
        for (auto& row : rows) {
            if (!row.contains("address") || !row["address"].is_string()) continue;
            const auto address = HexValue(row["address"].get<std::string>());
            const ModuleEntry* selected = nullptr;
            for (const auto& module : modules) if (address >= module.baseAddress && address - module.baseAddress < module.size) { selected = &module; break; }
            if (!selected) continue;
            const auto base = selected->baseAddress;
            const auto rva = HexAddr(address - base);
            size_t candidates = 0, moduleRecords = 0;
            for (const auto& entry : doc["entries"])
                if ((!labelsOnly || !entry.value("label", "").empty()) &&
                        !_stricmp(entry["module"].get_ref<const std::string&>().c_str(), selected->name.c_str())) {
                    ++moduleRecords; if (entry["rva"] == rva) ++candidates;
                }
            if (!moduleRecords) continue;
            if (previews >= 20) { rows[0]["analysis_annotations_truncated"] = true; continue; }
            if (!contexts.count(base)) {
                if (contexts.size() >= 16) { rows[0]["analysis_annotations_truncated"] = true; row["analysis_warning"] = "Module annotation lookup budget exhausted"; continue; }
                contexts[base] = AnnotationContext(address, modules);
                if (contexts[base].value("module_epoch", "") != beforeEpoch)
                    throw AnalysisError("analysis_target_changed", "Target modules changed or identity became unavailable; notes were not applied. Retry the lookup");
            }
            const auto& context = contexts.at(base);
            if (!reportedHistory.count(base)) {
                size_t previous = 0;
                for (const auto& entry : doc["entries"]) if (entry["module"] == context["module"] && entry["build_id"] != context["build_id"]) ++previous;
                if (previous) row["analysis_previous_records"] = previous;
                reportedHistory.insert(base);
            }
            if (!candidates) continue;
            const auto id = context["build_id"].get<std::string>() + "@" + rva;
            if (context["persistent_identity"].get<bool>() && doc["entries"].contains(id)) {
                const auto& entry = doc["entries"][id];
                if (labelsOnly && entry.value("label", "").empty()) continue;
                row["annotation"] = labelsOnly ? json{{"label", entry["label"]}} : Preview(entry);
                if (codeAvailable) row["annotation"]["stale"] = entry["original_bytes"] != Bytes(row["bytes"].get<std::string>());
                else row["annotation"]["code_validation"] = "not_checked";
                ++previews;
            } else { row["annotation_history"] = {{"count", candidates}, {"applied", false}}; ++previews; }
        }
        GetModuleIdentityResponse epoch{};
        if (!session_.GetModuleIdentity(0, epoch, error) || std::to_string(epoch.moduleEpoch) != beforeEpoch)
            throw AnalysisError("analysis_target_changed", "Target modules changed during inspection; notes were not applied. Retry the lookup");
        output = std::move(rows);
    } catch (const std::exception& error) { output[0]["analysis_warning"] = error.what(); }
}

void McpServer::AddAnnotationLabels(json& rows, const std::string& beforeEpoch) {
    if (beforeEpoch.empty() || rows.empty()) return;
    // Never enrich pending breakpoints or synthesize function-start annotations
    // for a stack return address. Only the exact returned address is eligible.
    json candidates = json::array(); std::vector<size_t> indexes;
    for (size_t i = 0; i < rows.size(); ++i) if (rows[i].contains("address") &&
            rows[i]["address"].is_string() && rows[i].value("status", "") != "pending") {
        candidates.push_back({{"address", rows[i]["address"]}}); indexes.push_back(i);
    }
    AddAnnotations(candidates, false, beforeEpoch, true);
    for (size_t i = 0; i < candidates.size(); ++i) if (candidates[i].contains("annotation"))
        rows[indexes[i]]["annotation"] = candidates[i]["annotation"];
    if (!candidates.empty() && candidates[0].value("analysis_annotations_truncated", false))
        rows[0]["analysis_annotations_truncated"] = true;
}

void McpServer::AddStopAnnotation(json& result, const json& args) {
    if (!JsonBool(args, "include_annotations", true) || result.contains("error") || !session_.IsAttached()) return;
    const bool stopped = result.value("stopped", false) || (result.value("success", false) && result.contains("instructionPointer"));
    if (!stopped || !result.contains("threadId") || !result["threadId"].is_number_unsigned()) return;
    const auto reason = result.value("reason", "");
    if (reason == "exit" || reason == "module-load") return; // module base is not an instruction pointer
    const auto field = result.contains("instructionPointer") ? "instructionPointer" : "address";
    if (!result.contains(field) || !result[field].is_string()) return;
    try {
        const auto epoch = AnnotationEpoch();
        if (epoch.empty()) return;
        const auto thread = result["threadId"].get<uint32_t>();
        const auto address = HexValue(result[field].get<std::string>());
        if (session_.QueryThreadStopped(thread) != std::optional<bool>(true)) return;
        const auto regs = session_.GetRegisters(thread);
        if (!regs || (regs->is32bit ? (regs->rip & UINT32_MAX) : regs->rip) != address) return;
        const auto code = session_.Disassemble(address, 1);
        if (code.empty()) return;
        json row = json::array({{{"address", result[field]}, {"bytes", code[0].bytes}}});
        AddAnnotations(row, true, epoch);
        if (row[0].contains("annotation")) result["annotation"] = row[0]["annotation"];
    } catch (...) { /* Optional notes cannot turn a valid stop into a tool failure. */ }
}
} // namespace veh
