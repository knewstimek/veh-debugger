import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as net from 'net';

export function activate(context: vscode.ExtensionContext) {
	const factory = new VehDebugAdapterFactory(context);
	context.subscriptions.push(
		vscode.debug.registerDebugAdapterDescriptorFactory('veh', factory)
	);
}

export function deactivate() {}

class VehDebugAdapterFactory implements vscode.DebugAdapterDescriptorFactory {
	constructor(private context: vscode.ExtensionContext) {}

	createDebugAdapterDescriptor(
		session: vscode.DebugSession,
		executable: vscode.DebugAdapterExecutable | undefined
	): vscode.ProviderResult<vscode.DebugAdapterDescriptor> {
		const config = session.configuration;

		// 어댑터 경로 결정
		let adapterPath = config.adapterPath || '';
		if (!adapterPath) {
			// 익스텐션 번들 내 bin/ → 개발 시 빌드 디렉토리 순서로 탐색
			const candidates = [
				path.join(this.context.extensionPath, 'bin', 'veh-debug-adapter.exe'),
				path.join(this.context.extensionPath, '..', 'build', 'bin', 'Release', 'veh-debug-adapter.exe'),
				path.join(this.context.extensionPath, '..', 'build', 'bin', 'Debug', 'veh-debug-adapter.exe'),
			];
			for (const p of candidates) {
				if (fs.existsSync(p)) {
					adapterPath = p;
					break;
				}
			}
		}

		if (!adapterPath) {
			vscode.window.showErrorMessage(
				'VEH Debug Adapter not found. Build the project or set "adapterPath" in launch.json.'
			);
			return undefined;
		}

		const adapterPort: number = config.adapterPort || 0;

		if (adapterPort > 0) {
			// TCP 모드: 어댑터를 TCP로 실행하고 소켓으로 연결
			const args: string[] = ['--tcp', `--port=${adapterPort}`];
			if (config.logFile) args.push(`--log=${config.logFile}`);
			if (config.logLevel) args.push(`--log-level=${config.logLevel}`);

			return new vscode.DebugAdapterServer(adapterPort, 'localhost');
		} else {
			// stdio 모드 (기본)
			const args: string[] = [];
			if (config.logFile) args.push(`--log=${config.logFile}`);
			if (config.logLevel) args.push(`--log-level=${config.logLevel}`);

			return new vscode.DebugAdapterExecutable(adapterPath, args);
		}
	}
}
