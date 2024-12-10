import logging
import mmguero
import pytest
import requests

LOGGER = logging.getLogger(__name__)

UPLOAD_ARTIFACTS = [
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/AutomatedTestingTools/WinDefender_Events_1117_1116_AtomicRedTeam.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Command and Control/bits_openvpn.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Command and Control/DE_RDP_Tunnel_5156.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Command and Control/DE_RDP_Tunneling_4624.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Command and Control/DE_sysmon-3-rdp-tun.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Command and Control/tunna_iis_rdp_smb_tunneling_sysmon_3.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/4794_DSRM_password_change_t1098.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/ACL_ForcePwd_SPNAdd_User_Computer_Accounts.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/babyshark_mimikatz_powershell.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/CA_chrome_firefox_opera_4663.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/CA_DCSync_4662.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/CA_hashdump_4663_4656_lsass_access.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/CA_keefarce_keepass_credump.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/CA_protectedstorage_5145_rpc_masterkey.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/CA_sysmon_hashdump_cmd_meterpreter.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/CA_teamviewer-dumper_sysmon_10.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/dc_applog_ntdsutil_dfir_325_326_327.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/etw_rpc_zerologon.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/kerberos_pwd_spray_4771.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/MSSQL_multiple_failed_logon_EventID_18456.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/remote_pwd_reset_rpc_mimikatz_postzerologon_target_DC.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/remote_sam_registry_access_via_backup_operator_priv.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/sysmon_10_11_lsass_memdump.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/sysmon_13_keylogger_directx.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/Sysmon_13_Local_Admin_Password_Changed.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/Sysmon13_MachineAccount_Password_Hash_Changed_via_LsarSetSecret.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/sysmon17_18_kekeo_tsssp_default_np.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/sysmon_rdrleakdiag_lsass_dump.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/tutto_malseclogon.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Credential Access/Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_104_system_log_cleared.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_1102_security_log_cleared.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_EventLog_Service_Crashed.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_Fake_ComputerAccount_4720.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/de_hiding_files_via_attrib_cmdlet.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_KernelDebug_and_TestSigning_ON_Security_4826.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/de_portforward_netsh_rdp_sysmon_13_1.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_Powershell_CLM_Disabled_Sysmon_12.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/de_powershell_execpolicy_changed_sysmon_13.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_ProcessHerpaderping_Sysmon_11_10_1_7.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/de_PsScriptBlockLogging_disabled_sysmon12_13.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_remote_eventlog_svc_crash_byt3bl33d3r_sysmon_17_1_3.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_renamed_psexec_service_sysmon_17_18.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_suspicious_remote_eventlog_svc_access_5145.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/de_sysmon_13_VBA_Security_AccessVBOM.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_UAC_Disabled_Sysmon_12_13.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_WinEventLogSvc_Crash_System_7036.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DE_xp_cmdshell_enabled_MSSQL_EID_15457.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/DSE_bypass_BYOV_TDL_dummydriver_sysmon_6_7_13.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/evasion_codeinj_odzhan_conhost_sysmon_10_1.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/evasion_codeinj_odzhan_spoolsv_sysmon_10_1.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/faxhell_sysmon_7_1_18_3_bindshell_dllhijack.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/meterpreter_migrate_to_explorer_sysmon_8.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/process_suspend_sysmon_10_ga_800.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/sideloading_wwlib_sysmon_7_1_11.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/sysmon_10_1_ppid_spoofing.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/Sysmon_10_Evasion_Suspicious_NtOpenProcess_CallTrace.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/Sysmon_12_DE_AntiForensics_MRU_DeleteKey.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/sysmon_13_rdp_settings_tampering.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/sysmon_2_11_evasion_timestomp_MACE.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/Sysmon 7 dllhijack_cdpsshims_CDPSvc.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/Sysmon 7  Update Session Orchestrator Dll Hijack.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Defense Evasion/Win_4985_T1186_Process_Doppelganging.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Discovery/4799_remote_local_groups_enumeration.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Discovery/dicovery_4661_net_group_domain_admins_target.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Discovery/discovery_bloodhound.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Discovery/discovery_enum_shares_target_sysmon_3_18.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Discovery/discovery_local_user_or_group_windows_security_4799_4798.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Discovery/discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Discovery/discovery_psloggedon.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Discovery/Discovery_Remote_System_NamedPipes_Sysmon_18.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Discovery/discovery_sysmon_18_Invoke_UserHunter_NetSessionEnum_DC-srvsvc.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Discovery/discovery_sysmon_3_Invoke_UserHunter_SourceMachine.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Discovery/discovery_UEFI_Settings_rweverything_sysmon_6.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/evasion_execution_imageload_wuauclt_lolbas.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_driveby_cve-2018-15982_sysmon_1_10.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_msxsl_xsl_sysmon_1_7.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_11_lolbin_rundll32_shdocvw_openurl.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_11_lolbin_rundll32_zipfldr_RouteTheCall.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_7_jscript9_defense_evasion.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_ftp.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_lolbin_pcalua.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_rundll32_pcwutl_LaunchApplication.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_lobin_regsvr32_sct.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/Exec_sysmon_meterpreter_reversetcp_msipackage.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/execution_evasion_visual_studio_prebuild_event.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/Exec_via_cpl_Application_Experience_EventID_17_ControlPanelApplet.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/exec_wmic_xsl_internet_sysmon_3_1_11.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/revshell_cmd_svchost_sysmon_1.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/rogue_msi_url_1040_1042.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/susp_explorer_exec.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/susp_explorer_exec_root_cmdline_@rimpq_@CyberRaiju.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/sysmon_11_1_lolbas_downldr_desktopimgdownldr.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/sysmon_1_11_rundll32_cpl_ostap.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/Sysmon_Exec_CompiledHTML.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/sysmon_exec_from_vss_persistence.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/sysmon_lolbas_rundll32_zipfldr_routethecall_shell.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/sysmon_lolbin_bohops_vshadow_exec.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/Sysmon_meterpreter_ReflectivePEInjection_to_notepad_.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/sysmon_vbs_sharpshooter_stageless_meterpreter.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/sysmon_zipexec.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/temp_scheduled_task_4698_4699.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Execution/windows_bits_4_59_60_lolbas desktopimgdownldr.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/lateral_movement_startup_3_11.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_5145_Remote_FileCopy.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_dcom_shwnd_shbrwnd_mmc20_failed_traces_system_10016.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_ImageLoad_NFSH_Sysmon_7.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_impacket_docmexec_mmc_sysmon_01.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_NewShare_Added_Sysmon_12_13.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_REMCOM_5145_TargetHost.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/lm_remote_registry_sysmon_1_13_3.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_Remote_Service01_5145_svcctl.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_Remote_Service02_7045.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_renamed_psexecsvc_5145.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_ScheduledTask_ATSVC_target_host.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_sysmon_1_12_13_3_tsclient_SharpRdp.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/lm_sysmon_18_remshell_over_namedpipe.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_sysmon_3_12_13_1_SharpRDP.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_sysmon_remote_task_src_powershell.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_tsclient_startup_folder.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_typical_IIS_webshell_sysmon_1_10_traces.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_winrm_exec_sysmon_1_winrshost.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_WMIC_4648_rpcss.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_wmiexec_impacket_sysmon_whoami.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/LM_xp_cmdshell_MSSQL_Events.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/MSSQL_15281_xp_cmdshell_exec_failed_attempt.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/net_share_drive_5142.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/powercat_revShell_sysmon_1_3.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/remote_file_copy_system_proc_file_write_sysmon_11.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/RemotePowerShell_MS_Windows-Remote_Management_EventID_169.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/remote task update 4624 4702 same logonid.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/sharprdp_sysmon_7_mstscax.dll.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/smb_bi_auth_conn_spoolsample.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/smbmap_upload_exec_sysmon.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/spoolsample_5145.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/sysmon_1_exec_via_sql_xpcmdshell.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Lateral Movement/wmi_remote_registry_sysmon.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Other/emotet/exec_emotet_ps_4104.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Other/emotet/exec_emotet_ps_800_get-item.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Other/emotet/exec_emotet_ps_800_invoke-item.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Other/emotet/exec_emotet_ps_800_new-item.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Other/emotet/exec_emotet_ps_800_new-object.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Other/emotet/exec_emotet_sysmon_1.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Other/maldoc_mshta_via_shellbrowserwind_rundll32.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/Network_Service_Guest_added_to_admins_4732.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/persistence_accessibility_features_osk_sysmon1.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/persistence_hidden_local_account_sysmon.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/persistence_pendingGPO_sysmon_13.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/persistence_security_dcshadow_4742.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/Persistence_Shime_Microsoft-Windows-Application-Experience_Program-Telemetry_500.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/persistence_SilentProcessExit_ImageHijack_sysmon_13_1.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/persistence_startup_UserShellStartup_Folder_Changed_sysmon_13.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/persistence_sysmon_11_13_1_shime_appfix.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/Persistence_Winsock_Catalog Change EventId_1.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/persist_turla_outlook_backdoor_comhijack.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/persist_valid_account_guest_rid_hijack.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/sysmon_13_1_persistence_via_winlogon_shell.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/sysmon_1_smss_child_proc_bootexecute_setupexecute.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/sysmon_local_account_creation_and_added_admingroup_12_13.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Persistence/wmighost_sysmon_20_21_1.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/4624 LT3 AnonymousLogon Localhost - JuicyPotato.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/4765_sidhistory_add_t1178.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/CVE-2020-0796_SMBV3Ghost_LocalPrivEsc_Sysmon_3_1_10.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/eop_appcontainer_il_broker_filewrite.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Invoke_TokenDuplication_UAC_Bypass4624.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/NTLM2SelfRelay-med0x2e-security_4624_4688.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/PrivEsc_CVE-2020-1313_Sysmon_13_UScheduler_Cmdline.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/PrivEsc_Imperson_NetSvc_to_Sys_Decoder_Sysmon_1_17_18.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/privesc_KrbRelayUp_windows_4624.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/PrivEsc_NetSvc_SessionToken_Retrival_via_localSMB_Auth_5145.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/privesc_registry_symlink_CVE-2020-1377.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/privesc_roguepotato_sysmon_17_18.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/privesc_rotten_potato_from_webshell_metasploit_sysmon_1_8_3.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/privesc_seimpersonate_tosys_spoolsv_sysmon_17_18.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/privesc_spoolfool_mahdihtm_sysmon_1_11_7_13.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/privesc_spoolsv_spl_file_write_sysmon11.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/privesc_sysmon_cve_20201030_spooler.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/privesc_unquoted_svc_sysmon_1_11.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/privexchange_dirkjan.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/RogueWinRM.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Runas_4624_4648_Webshell_CreateProcessAsUserA.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/samaccount_spoofing_CVE-2021-42287_CVE-2021-42278_DC_securitylogs.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/security_4624_4673_token_manip.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_11_1_15_WScriptBypassUAC.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_11_1_7_uacbypass_cliconfg.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_1_11_exec_as_system_via_schedtask.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_1_13_11_cmstp_ini_uacbypass.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_1_13_UACBypass_AppPath_Control.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_11_7_1_uacbypass_windirectory_mocking.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_13_1_12_11_perfmonUACBypass.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_13_1_compmgmtlauncherUACBypass.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_13_1_meterpreter_getsystem_NamedPipeImpersonation.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_13_1_UACBypass_SDCLTBypass.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_1_7_11_mcx2prov_uacbypass.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_1_7_11_migwiz.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_1_7_11_sysprep_uacbypass.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_1_7_elevate_uacbypass_sysprep.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_privesc_from_admin_to_system_handle_inheritance.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_privesc_psexec_dwell.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/sysmon_uacbypass_CDSSync_schtask_hijack_byeintegrity5.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_22.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_23.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_30.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_32.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_33.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_34.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_36_FileCreate.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_37_FileCreate.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_38.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_39.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_41.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_43.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_45.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_53.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_54.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_56.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_uacme_58.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_63.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_64.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/System_7045_namedpipe_privesc.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/UACME_59_Sysmon.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/UACME_61_Changepk.evtx",
    # "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/Privilege Escalation/win10_4703_SeDebugPrivilege_enabled.evtx",
    "evtx/sbousseaden-EVTX-ATTACK-SAMPLES/UACME_59_Sysmon.evtx",
]


@pytest.mark.mapi
@pytest.mark.pcap
def test_all_evtx(
    malcolm_http_auth,
    malcolm_url,
    pcap_hash_map,  # actually pcap_hash_map holds evtx files too...
):
    assert all([pcap_hash_map.get(x, None) for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])

    response = requests.post(
        f"{malcolm_url}/mapi/agg/event.dataset",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "doctype": "host",
            "filter": {
                "event.module": "winlog",
                "!event.dataset": None,
                "tags": [pcap_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
            },
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    buckets = {
        item['key']: item['doc_count'] for item in mmguero.DeepGet(response.json(), ['event.dataset', 'buckets'], [])
    }
    LOGGER.debug(buckets)
    assert buckets
