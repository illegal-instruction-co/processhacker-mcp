#include "VehButNot.h"

#include <TlHelp32.h>
#include <format>
#include <iostream>

using namespace std;

using namespace machinetherapist;

VehButNot* VehButNot::_instance = nullptr;

VehButNot::~VehButNot()
{
	Shutdown();
	if (_instance == this)
		_instance = nullptr;
}

KiUedCallback* VehButNot::FindKiUedCallbackPointer(HMODULE ntdll)
{
	auto* base = reinterpret_cast<uint8_t*>(GetProcAddress(ntdll, "KiUserExceptionDispatcher"));
	if (!base)
		return nullptr;

	for (int i = 0; i < 64; i++) {
		const auto match =
			base[i] == 0x48 && base[i + 1] == 0x8B && base[i + 2] == 0x05 && base[i + 7] == 0x48 && base[i + 8] == 0x85 && base[i + 9] == 0xC0;
		if (!match)
			continue;

		const auto disp = *reinterpret_cast<int32_t*>(&base[i + 3]);
		auto* resolved = &base[i] + 7 + disp;
		return reinterpret_cast<KiUedCallback*>(resolved);
	}

	return nullptr;
}

WnfSubscriptionTable** VehButNot::FindWnfSubscriptionTable(HMODULE ntdll)
{
	auto* peBase = reinterpret_cast<uint8_t*>(ntdll);
	const auto* dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(peBase);
	const auto* ntHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(peBase + dosHdr->e_lfanew);
	const auto* sections = IMAGE_FIRST_SECTION(ntHdrs);

	uint8_t* dataStart = nullptr;
	uint8_t* dataEnd = nullptr;

	for (WORD s = 0; s < ntHdrs->FileHeader.NumberOfSections; s++) {
		if (memcmp(sections[s].Name, ".data", 5) == 0) {
			dataStart = peBase + sections[s].VirtualAddress;
			dataEnd = dataStart + sections[s].Misc.VirtualSize;
			break;
		}
	}

	if (!dataStart)
		return nullptr;

	auto* exportAddr = reinterpret_cast<uint8_t*>(GetProcAddress(ntdll, "RtlSubscribeWnfStateChangeNotification"));
	if (!exportAddr)
		return nullptr;

	uint8_t* innerFunc = nullptr;
	for (int i = 0; i < 64; i++) {
		if (exportAddr[i] == 0xE8) {
			const auto callDisp = *reinterpret_cast<int32_t*>(&exportAddr[i + 1]);
			innerFunc = &exportAddr[i] + 5 + callDisp;
			break;
		}
	}

	if (!innerFunc)
		return nullptr;

	for (int i = 0; i < _maxPatternScan; i++) {
		if (innerFunc[i] != 0x48 || innerFunc[i + 1] != 0x8D)
			continue;

		if ((innerFunc[i + 2] & 0x07) != 0x05)
			continue;

		const auto disp = *reinterpret_cast<int32_t*>(&innerFunc[i + 3]);
		auto* target = &innerFunc[i] + 7 + disp;

		if (target >= dataStart && target < dataEnd)
			return reinterpret_cast<WnfSubscriptionTable**>(target + 8);
	}

	return nullptr;
}

void NTAPI VehButNot::OnException(PEXCEPTION_RECORD exceptionRecord, PCONTEXT context)
{
	auto* self = _instance;
	if (!self)
		return;

	if (exceptionRecord->ExceptionCode != StatusSingleStep)
		return;

	if ((context->Dr6 & 0x01) && reinterpret_cast<PVOID>(context->Rip) == self->_config.targetApi) {
		self->_interceptionCount.fetch_add(1);

		if (self->_config.handler)
			self->_config.handler(self->_config.targetApi, context, self->_config.userData);

		context->EFlags |= EflagsResume;
		context->Dr6 = 0;

		if (!self->_config.persistentHook) {
			context->Dr0 = 0;
			context->Dr7 &= ~Dr7ArmDr0Execute;
		}

		self->_rtlRestoreContext(context, nullptr);
		return;
	}

	if ((context->Dr6 & 0x02) && reinterpret_cast<PVOID>(context->Rip) == reinterpret_cast<PVOID>(self->_ntGetContextThread)) {
		static atomic<bool> scrubGuard{false};

		if (!self->_drHidingActive.load() || scrubGuard.exchange(true)) {
			context->EFlags |= EflagsResume;
			context->Dr6 = 0;
			self->_rtlRestoreContext(context, nullptr);
			return;
		}

		auto threadHandle = reinterpret_cast<HANDLE>(context->Rcx);
		auto* outCtx = reinterpret_cast<PCONTEXT>(context->Rdx);

		const auto status = self->_ntGetContextThread(threadHandle, outCtx);

		if (status >= 0 && outCtx && (outCtx->ContextFlags & 0x00100010)) {
			outCtx->Dr0 = 0;
			outCtx->Dr1 = 0;
			outCtx->Dr2 = 0;
			outCtx->Dr3 = 0;
			outCtx->Dr6 = 0;
			outCtx->Dr7 = 0;
		}

		context->Rax = static_cast<DWORD64>(status);
		context->Rip = *reinterpret_cast<uint64_t*>(context->Rsp);
		context->Rsp += 8;
		context->EFlags |= EflagsResume;
		context->Dr6 = 0;

		scrubGuard.store(false);
		self->_rtlRestoreContext(context, nullptr);
		return;
	}
}

NTSTATUS NTAPI VehButNot::OnWnfStateChange(WnfStateName, WnfChangeStamp, WnfTypeId*, PVOID callbackContext, PVOID, ULONG)
{
	auto* self = reinterpret_cast<VehButNot*>(callbackContext);
	if (!self || !self->_config.targetApi)
		return 0;

	auto expected = false;
	if (!self->_armed.compare_exchange_strong(expected, true))
		return 0;

	self->ArmAllThreads(self->_config.targetApi);
	return 0;
}

bool VehButNot::SetHardwareBreakpoint(HANDLE thread, PVOID address)
{
	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(thread, &ctx))
		return false;

	ctx.Dr0 = reinterpret_cast<DWORD64>(address);
	ctx.Dr7 &= ~Dr7Dr0Mask;
	ctx.Dr7 |= Dr7ArmDr0Execute;

	if (_config.enableDrHiding && _ntGetContextThread) {
		ctx.Dr1 = reinterpret_cast<DWORD64>(_ntGetContextThread);
		ctx.Dr7 &= ~Dr7Dr1Mask;
		ctx.Dr7 |= Dr7ArmDr1Execute;
	}

	ctx.Dr6 = 0;
	return SetThreadContext(thread, &ctx);
}

bool VehButNot::ClearHardwareBreakpoint(HANDLE thread)
{
	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(thread, &ctx))
		return false;

	ctx.Dr0 = 0;
	ctx.Dr1 = 0;
	ctx.Dr7 &= ~(Dr7ArmDr0Execute | Dr7ArmDr1Execute);
	ctx.Dr6 = 0;
	return SetThreadContext(thread, &ctx);
}

void VehButNot::ArmAllThreads(PVOID address)
{
	const auto pid = GetCurrentProcessId();
	const auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return;

	THREADENTRY32 te{};
	te.dwSize = sizeof(te);

	if (Thread32First(snap, &te)) {
		do {
			if (te.th32OwnerProcessID != pid)
				continue;

			const auto hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
			if (!hThread)
				continue;

			static_cast<void>(SetHardwareBreakpoint(hThread, address));
			CloseHandle(hThread);
		} while (Thread32Next(snap, &te));
	}

	CloseHandle(snap);
}

void VehButNot::DisarmAllThreads()
{
	const auto pid = GetCurrentProcessId();
	const auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return;

	THREADENTRY32 te{};
	te.dwSize = sizeof(te);

	if (Thread32First(snap, &te)) {
		do {
			if (te.th32OwnerProcessID != pid)
				continue;

			const auto hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
			if (!hThread)
				continue;

			static_cast<void>(ClearHardwareBreakpoint(hThread));
			CloseHandle(hThread);
		} while (Thread32Next(snap, &te));
	}

	CloseHandle(snap);
}

bool VehButNot::InstallExceptionPreFilter()
{
	_kiUedCallbackPtr = FindKiUedCallbackPointer(_ntdll);
	if (!_kiUedCallbackPtr)
		return false;

	_originalCallback = *_kiUedCallbackPtr;

	DWORD oldProtect = 0;
	if (!VirtualProtect(_kiUedCallbackPtr, sizeof(KiUedCallback), PAGE_READWRITE, &oldProtect))
		return false;

	*_kiUedCallbackPtr = &VehButNot::OnException;

	VirtualProtect(_kiUedCallbackPtr, sizeof(KiUedCallback), oldProtect, &oldProtect);
	return true;
}

bool VehButNot::SetupWnfSubscription()
{
	const auto subscribe = reinterpret_cast<RtlSubscribeWnfFn>(GetProcAddress(_ntdll, "RtlSubscribeWnfStateChangeNotification"));
	if (!subscribe)
		return false;

	const auto status = subscribe(&_wnfSubscription, _config.wnfStateName, 0, &VehButNot::OnWnfStateChange, this, nullptr, 0, 0);
	return status >= 0;
}

bool VehButNot::Initialize(const VehButNotConfig& config)
{
	if (_initialized)
		return false;

	_config = config;
	_instance = this;

	_ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!_ntdll)
		return false;

	_rtlRestoreContext = reinterpret_cast<RtlRestoreContextFn>(GetProcAddress(_ntdll, "RtlRestoreContext"));
	_ntUpdateWnfState = reinterpret_cast<NtUpdateWnfStateFn>(GetProcAddress(_ntdll, "NtUpdateWnfStateData"));

	if (_config.enableDrHiding)
		_ntGetContextThread = reinterpret_cast<NtGetContextThreadFn>(GetProcAddress(_ntdll, "NtGetContextThread"));

	if (!_rtlRestoreContext)
		return false;

	if (!InstallExceptionPreFilter())
		return false;

	if (!SetupWnfSubscription()) {
		DWORD oldP;
		VirtualProtect(_kiUedCallbackPtr, sizeof(PVOID), PAGE_READWRITE, &oldP);
		*_kiUedCallbackPtr = _originalCallback;
		VirtualProtect(_kiUedCallbackPtr, sizeof(PVOID), oldP, &oldP);
		return false;
	}

	_initialized = true;
	return true;
}

bool VehButNot::ArmViaWnf()
{
	if (!_initialized || !_ntUpdateWnfState)
		return ArmDirect();

	auto stateName = _config.wnfStateName;
	uint32_t dummy = 0xDEADBEEF;
	const auto status = _ntUpdateWnfState(&stateName, &dummy, sizeof(dummy), nullptr, nullptr, 0, 0);

	if (status < 0)
		return ArmDirect();

	Sleep(100);
	const auto armed = _armed.load() ? true : ArmDirect();

	if (armed) {
		CleanupWnfSubscription();
		if (_config.enableDrHiding && _ntGetContextThread)
			_drHidingActive.store(true);
	}

	return armed;
}

bool VehButNot::ArmDirect()
{
	auto expected = false;
	if (!_armed.compare_exchange_strong(expected, true))
		return true;

	return SetHardwareBreakpoint(GetCurrentThread(), _config.targetApi);
}

void VehButNot::Shutdown()
{
	if (!_initialized)
		return;

	_drHidingActive.store(false);

	DisarmAllThreads();
	_armed.store(false);

	if (_kiUedCallbackPtr) {
		DWORD oldP;
		VirtualProtect(_kiUedCallbackPtr, sizeof(PVOID), PAGE_READWRITE, &oldP);
		*_kiUedCallbackPtr = _originalCallback;
		VirtualProtect(_kiUedCallbackPtr, sizeof(PVOID), oldP, &oldP);
		_kiUedCallbackPtr = nullptr;
	}

	CleanupWnfSubscription();
	_initialized = false;
}

void VehButNot::CleanupWnfSubscription()
{
	if (!_wnfSubscription)
		return;

	const auto unsub = reinterpret_cast<RtlUnsubscribeWnfFn>(GetProcAddress(_ntdll, "RtlUnsubscribeWnfNotificationWaitForCompletion"));
	if (unsub)
		unsub(_wnfSubscription);
	_wnfSubscription = nullptr;
}

bool VehButNot::DumpSubscriptions(HMODULE ntdll)
{
	auto** ppTable = FindWnfSubscriptionTable(ntdll);
	if (!ppTable || !*ppTable)
		return false;

	const auto* table = *ppTable;
	cout << format("[*] WnfSubscriptionTable @ 0x{:016X}\n", reinterpret_cast<uintptr_t>(table)) << format("[*] Magic: 0x{:08X}\n", table->magic);

	const auto xorFlag = table->rbTreeFlags & 1;
	const auto treeRootAddr = reinterpret_cast<uintptr_t>(&table->rbTreeRoot);
	auto* rawRoot = table->rbTreeRoot;

	if (xorFlag && rawRoot)
		rawRoot = reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(rawRoot) ^ treeRootAddr);

	if (!rawRoot) {
		cout << "[*] RB-tree is empty\n";
		return true;
	}

	const auto decode = [xorFlag](RtlBalancedNode* parent, RtlBalancedNode* encoded) -> RtlBalancedNode* {
		if (!encoded)
			return nullptr;
		if (xorFlag)
			return reinterpret_cast<RtlBalancedNode*>(reinterpret_cast<uintptr_t>(encoded) ^ reinterpret_cast<uintptr_t>(parent));
		return encoded;
	};

	const auto rbNodeToNameSub = [](RtlBalancedNode* node) -> const WnfNameSubscription* {
		return reinterpret_cast<const WnfNameSubscription*>(reinterpret_cast<uint8_t*>(node) - offsetof(WnfNameSubscription, rbNode));
	};

	const auto treeMinimum = [&decode](RtlBalancedNode* node) -> RtlBalancedNode* {
		auto* parent = static_cast<RtlBalancedNode*>(nullptr);
		while (true) {
			auto* left = decode(parent, node->children[0]);
			if (!left)
				return node;
			parent = node;
			node = left;
		}
	};

	const auto treeSuccessor = [&decode](RtlBalancedNode* node) -> RtlBalancedNode* {
		auto* right = decode(node, node->children[1]);
		if (right) {
			auto* cursor = right;
			while (true) {
				auto* left = decode(node, cursor->children[0]);
				if (!left)
					return cursor;
				node = cursor;
				cursor = left;
			}
		}
		return nullptr;
	};

	auto* rbRoot = reinterpret_cast<RtlBalancedNode*>(rawRoot);
	auto* current = treeMinimum(rbRoot);
	int nameCount = 0;

	while (current && nameCount < _maxListWalk) {
		const auto* nameSub = rbNodeToNameSub(current);

		cout << format("\n  [{}] StateName: 0x{:016X}  Subs: {}\n", nameCount, nameSub->stateName, nameSub->totalSubscriptions);

		const auto* userHead = &nameSub->userSubscriptionsHead;
		auto* userEntry = userHead->Flink;
		int userCount = 0;

		while (userEntry != userHead && userCount < 256) {
			const auto* userSub =
				reinterpret_cast<const WnfUserSubscription*>(reinterpret_cast<const uint8_t*>(userEntry) - offsetof(WnfUserSubscription, listEntry));

			cout << format("      Callback: 0x{:016X}  Context: 0x{:016X}\n", reinterpret_cast<uintptr_t>(userSub->callback),
						   reinterpret_cast<uintptr_t>(userSub->callbackContext));

			userEntry = userEntry->Flink;
			userCount++;
		}

		current = treeSuccessor(current);
		nameCount++;
	}

	cout << format("\n[*] Total: {} name subscriptions\n", nameCount);
	return true;
}
