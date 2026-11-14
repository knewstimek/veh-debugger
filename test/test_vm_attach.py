"""Explicit VM namespace against a host fixture, with no target process."""
import json
import os
from pathlib import Path
import tempfile
from build_paths import RELEASE
from mcp_test_client import McpClient
FIXTURE=Path(RELEASE)/'guest_backend_fixture.exe'

def run():
    client=McpClient()
    try:
        client.initialize()
        guest={'pid':2147418112,'agent':str(FIXTURE),'target_scope':'guest'}
        assert client.tool('veh_attach',guest).get('success')
        vm={'agent':str(FIXTURE),'target_scope':'vm','agent_args':['--metadata','machine']}
        assert 'error' in client.tool('veh_attach',{**vm,'pid':1})
        assert client.tool('veh_threads')['count']==1,'invalid VM request replaced prior session'
        attached=client.tool('veh_attach',vm)
        assert attached.get('success') and attached['backend']['targetScope']=='vm' and 'pid' not in attached and 'addressBits' not in attached,attached
        assert not attached['backend']['stopsThreads'],attached
        listed=client.tool('veh_toolbox',{'operation':'call','tool':'veh_processes','arguments':{}})['result']
        assert listed['count']==2 and listed['processes']==[
            {'pid':4,'addressBits':64,'name':'System'},
            {'pid':4242,'addressBits':32,'name':'sample32.exe'}],listed
        batched=client.tool('veh_batch',{'steps':[{'tool':'veh_processes','args':{}}]})
        assert batched['failed']==0 and batched['results'][0]['result']==listed,batched
        assert 'error' in client.tool('veh_system_memory',{'operation':'search','space':'physical','address':'0x0','size':16,'pattern':'90'})
        assert client.tool('veh_virtual_machine',{'operation':'status'})['state']=='paused'
        traced=client.tool('veh_virtual_machine',{'operation':'trace','max_instructions':137})
        assert traced.get('success') and traced['completed']==137 and traced['lost']==73,traced
        rejected=client.tool('veh_launch',{'program':'host-not-created.exe',**vm})
        assert 'error' in rejected
        assert client.tool('veh_virtual_machine',{'operation':'status'})['state']=='paused'
        for mode in ('machine-process-short','machine-process-invalid','machine-process-error'):
            assert client.tool('veh_attach',{**vm,'agent_args':['--metadata',mode]}).get('success')
            result=client.tool('veh_toolbox',{'operation':'call','tool':'veh_processes','arguments':{}})['result']
            assert 'error' in result,(mode,result)
        for mode in ('machine-thread-error','machine-thread-short','machine-thread-name'):
            assert client.tool('veh_attach',{**vm,'agent_args':['--metadata',mode]}).get('success')
            result=client.tool('veh_toolbox',{'operation':'call','tool':'veh_threads','arguments':{}})['result']
            assert 'error' in result,(mode,result)
        for mode in ('machine-wrong-pid','machine-bad-width','machine-wrong-scope','machine-guest-cap','machine-truncated'):
            failed=client.tool('veh_attach',{**vm,'agent_args':['--metadata',mode]})
            assert 'error' in failed,(mode,failed)
            assert 'error' in client.tool('veh_virtual_machine',{'operation':'status'}),mode
        assert 'error' in client.tool('veh_attach',{'target_scope':'vm'})
        with tempfile.TemporaryDirectory(prefix='veh-vm-backend-') as temp:
            table=Path(temp)/'backends.json'
            table.write_text(json.dumps({'machine':{'path':str(FIXTURE),'args':['--metadata','machine'],'target_scope':'vm'},
                'guest':{'path':str(FIXTURE),'target_scope':'guest'}}),encoding='utf-8')
            with McpClient(env=dict(os.environ,VEH_BACKENDS=str(table))) as registered:
                registered.initialize()
                def processes(arguments):
                    return registered.tool('veh_toolbox',{'operation':'call','tool':'veh_processes','arguments':arguments})['result']
                # Discovery before any session, so a guest PID needs no VM attach/detach round trip.
                assert processes({'backend':'machine'})==listed
                assert 'error' in registered.tool('veh_threads'),'one-shot process query left a session'
                assert 'target_scope=vm' in processes({'backend':'guest'}).get('error',''),'non-VM backend accepted'
                assert 'error' in processes({'backend':'missing'})
                assert registered.tool('veh_attach',{'backend':'machine'}).get('success')
                assert 'omit it' in processes({'backend':'machine'}).get('error',''),'one-shot query beside a session'
                assert processes({})==listed
                assert registered.tool('veh_detach').get('success')
        with McpClient(env=dict(os.environ,VEH_MCP_PROFILE='full')) as full:
            full.initialize()
            assert full.tool('veh_attach',vm).get('success')
            assert full.tool('veh_processes')==listed
            assert 'error' in full.tool('veh_processes',{'unexpected':1})
            assert full.tool('veh_detach').get('success')
        print('PASS VM no-PID routing, process list direct/toolbox/batch/errors/sessionless, metadata rejection and VM control/trace')
    finally:client.close(terminate_target=False)

if __name__=='__main__':run()
