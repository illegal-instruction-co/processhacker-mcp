#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>

namespace machinetherapist {

	using WnfStateName = uint64_t;
	using WnfChangeStamp = uint32_t;

	struct WnfTypeId final {
		GUID typeId;
	};

	inline constexpr NTSTATUS StatusSingleStep = 0x80000004;
	inline constexpr uint32_t EflagsResume = 0x00010000;
	inline constexpr uint64_t Dr7ArmDr0Execute = 0x01;
	inline constexpr uint64_t Dr7Dr0Mask = 0x000F0003;
	inline constexpr uint64_t Dr7ArmDr1Execute = 0x04;
	inline constexpr uint64_t Dr7Dr1Mask = 0x00F0000C;
	inline constexpr WnfStateName WnfShelApplicationStarted = 0x0D83063EA3BDF875ULL;

	using WnfUserCallback = NTSTATUS(NTAPI*)(WnfStateName, WnfChangeStamp, WnfTypeId*, PVOID, PVOID, ULONG);
	using KiUedCallback = void(NTAPI*)(PEXCEPTION_RECORD, PCONTEXT);
	using RtlRestoreContextFn = void(NTAPI*)(PCONTEXT, PEXCEPTION_RECORD);
	using RtlSubscribeWnfFn = NTSTATUS(NTAPI*)(PVOID*, WnfStateName, WnfChangeStamp, WnfUserCallback, PVOID, WnfTypeId*, ULONG, ULONG);
	using RtlUnsubscribeWnfFn = NTSTATUS(NTAPI*)(PVOID);
	using NtUpdateWnfStateFn = NTSTATUS(NTAPI*)(WnfStateName*, PVOID, ULONG, WnfTypeId*, PVOID, WnfChangeStamp, ULONG);
	using NtGetContextThreadFn = NTSTATUS(NTAPI*)(HANDLE, PCONTEXT);

	struct RtlBalancedNode final {
		RtlBalancedNode* children[2];
		union {
			uint8_t red;
			uintptr_t parentValue;
		};
	};

	// size 0xA0, magic = 0xA00914
	struct WnfUserSubscription final {
		uint32_t magic;				// +0x00  0xA00914
		uint32_t padding0;			// +0x04
		LIST_ENTRY listEntry;		// +0x08
		PVOID nameSubscription;		// +0x18
		uint64_t refCount;			// +0x20
		WnfUserCallback callback;	// +0x28
		PVOID callbackContext;		// +0x30
		PVOID subProcessTag;		// +0x38
		WnfChangeStamp changeStamp; // +0x40
		uint32_t flags;				// +0x44
		uint32_t deliveryOptions;	// +0x48
	};

	static_assert(offsetof(WnfUserSubscription, callback) == 0x28);
	static_assert(offsetof(WnfUserSubscription, listEntry) == 0x08);

	// size 0x98, magic = 0x980912
	// RB node at +0x20, inserted via RtlRbInsertNodeEx(table+0x10, ...)
	struct WnfNameSubscription final {
		uint32_t magic;					   // +0x00  0x980912
		uint32_t padding0;				   // +0x04
		uint64_t reserved0;				   // +0x08
		WnfStateName stateName;			   // +0x10
		WnfChangeStamp currentChangeStamp; // +0x18
		uint32_t padding1;				   // +0x1C
		RtlBalancedNode rbNode;			   // +0x20  (0x18 bytes)
		uint64_t reserved1;				   // +0x38
		SRWLOCK subscriptionLock;		   // +0x40
		LIST_ENTRY userSubscriptionsHead;  // +0x48
		uint64_t refCount;				   // +0x58
		uint32_t totalSubscriptions;	   // +0x60
		uint32_t activeSubscriptions;	   // +0x64
		uint32_t deliveryCounters[5];	   // +0x68
		uint32_t flags;					   // +0x7C
	};

	static_assert(offsetof(WnfNameSubscription, stateName) == 0x10);
	static_assert(offsetof(WnfNameSubscription, rbNode) == 0x20);
	static_assert(offsetof(WnfNameSubscription, subscriptionLock) == 0x40);
	static_assert(offsetof(WnfNameSubscription, userSubscriptionsHead) == 0x48);
	static_assert(offsetof(WnfNameSubscription, totalSubscriptions) == 0x60);

	// size 0x58, magic = 0x580911
	// RB-tree root at +0x10, names list (legacy) at +0x20
	// RtlpWnfProcessSubscriptions @ 0x1801ce200
	struct WnfSubscriptionTable final {
		uint32_t magic;				// +0x00  0x580911
		uint32_t padding0;			// +0x04
		SRWLOCK tableLock;			// +0x08
		uint8_t* rbTreeRoot;		// +0x10  RTL_RB_TREE root
		uintptr_t rbTreeFlags;		// +0x18  encoded XOR flag
		LIST_ENTRY namesTableEntry; // +0x20  (legacy linked list)
		uint64_t reserved0;			// +0x30
		uint32_t timerDelayMs;		// +0x38
		uint32_t timerPeriodMs;		// +0x3C
		uint32_t timerMaxMs;		// +0x40
		uint32_t timerMaxCount;		// +0x44
		PVOID tpTimer;				// +0x48
		uint64_t reserved1;			// +0x50
	};

	static_assert(offsetof(WnfSubscriptionTable, tableLock) == 0x08);
	static_assert(offsetof(WnfSubscriptionTable, rbTreeRoot) == 0x10);
	static_assert(offsetof(WnfSubscriptionTable, namesTableEntry) == 0x20);
	static_assert(sizeof(WnfSubscriptionTable) == 0x58);

}
