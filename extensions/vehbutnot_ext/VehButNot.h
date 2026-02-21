#pragma once

#include "Types.h"

#include <atomic>
#include <cstdint>

namespace machinetherapist {

	using InterceptionCallback = bool (*)(PVOID targetAddress, PCONTEXT context, PVOID userData);

	struct VehButNotConfig final {
		PVOID targetApi = nullptr;
		InterceptionCallback handler = nullptr;
		PVOID userData = nullptr;
		WnfStateName wnfStateName = WnfShelApplicationStarted;
		bool persistentHook = true;
		bool enableDrHiding = true;
	};

	class VehButNot final {
	public:
		~VehButNot();

		VehButNot() = default;
		VehButNot(const VehButNot&) = delete;
		VehButNot& operator=(const VehButNot&) = delete;

		[[nodiscard]] inline int32_t GetInterceptionCount() const noexcept
		{
			return _interceptionCount.load();
		}

		[[nodiscard]] bool Initialize(const VehButNotConfig& config);
		[[nodiscard]] bool ArmViaWnf();
		[[nodiscard]] bool ArmDirect();
		void Shutdown();

		[[nodiscard]] static bool DumpSubscriptions(HMODULE ntdll);

	private:
		static constexpr int32_t _maxPatternScan = 512;
		static constexpr int32_t _maxListWalk = 1024;

		static VehButNot* _instance;

		VehButNotConfig _config{};
		HMODULE _ntdll = nullptr;
		KiUedCallback* _kiUedCallbackPtr = nullptr;
		KiUedCallback _originalCallback = nullptr;
		PVOID _wnfSubscription = nullptr;
		RtlRestoreContextFn _rtlRestoreContext = nullptr;
		NtUpdateWnfStateFn _ntUpdateWnfState = nullptr;
		NtGetContextThreadFn _ntGetContextThread = nullptr;
		std::atomic<int32_t> _interceptionCount{0};
		std::atomic<bool> _armed{false};
		std::atomic<bool> _drHidingActive{false};
		bool _initialized = false;

		[[nodiscard]] static KiUedCallback* FindKiUedCallbackPointer(HMODULE ntdll);
		[[nodiscard]] static WnfSubscriptionTable** FindWnfSubscriptionTable(HMODULE ntdll);

		static void NTAPI OnException(PEXCEPTION_RECORD exceptionRecord, PCONTEXT context);
		static NTSTATUS NTAPI OnWnfStateChange(WnfStateName, WnfChangeStamp, WnfTypeId*, PVOID, PVOID, ULONG);

		[[nodiscard]] bool InstallExceptionPreFilter();
		[[nodiscard]] bool SetupWnfSubscription();
		[[nodiscard]] bool SetHardwareBreakpoint(HANDLE thread, PVOID address);
		[[nodiscard]] bool ClearHardwareBreakpoint(HANDLE thread);
		void ArmAllThreads(PVOID address);
		void DisarmAllThreads();
		void CleanupWnfSubscription();
	};

}
