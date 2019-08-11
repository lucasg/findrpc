findrpc : Ida script to extract RPC interface from binaries
=============================================================

Installation
------------

Just run the script `findrpc.py`.


Features
------------

* View in a glance which RPC clients and servers are embedded in the binary :

![](screenshot/sgrm_broker.PNG)

* Locate dispatch tables for RPC servers:

![](screenshot/sgrm_broker_dispatch_table.PNG)


Study Example #1 : SgrmBroker
-----------------------------

Some RPC servers are not accessible via RpcView or NtObjectManager, although any clients can connect to it. One prime example is `SgrmBroker` which is a service running as PPL on Windows 10. Protected Processes Light (PPL) are famously protected against remote process memory reading, even if thoses processes are running as admin, thus why RpcView fail at localizing the interface.

`findrpc` can find it since it rely only on the binary :


Decompiled Interface :

```idl
// DllOffset: 0x2C9C0
// DllPath O:\Legifrance\binaries\findrpc\SgrmBroker_10.0.18362.1_WinBuild.160101.0800_2DF8A183.exe
// Complex Types:
/* Memory Size: 132 */
struct Struct_0 {
    /* Offset: 0 */ sbyte[128] Member0;
    /* Offset: 128 */ int Member1;
};


[uuid("7a20fcec-dec4-4c59-be57-212e8f65d3de"), version(1.0)]
interface intf_7a20fcec_dec4_4c59_be57_212e8f65d3de {

    HRESULT SgrmCreateSession(
    	/* Stack Offset: 0 */ handle_t p0, 
    	/* Stack Offset: 8 */ [In] wchar_t[1]* p1, 
    	/* Stack Offset: 16 */ [In] struct Struct_0* p2, 
    	/* Stack Offset: 24 */ [Out] /* FC_BIND_CONTEXT */ handle_t* p3, 
    	/* Stack Offset: 32 */ [Out] UIntPtr* p4
    );

    HRESULT SgrmEndSession(
    	/* Stack Offset: 0 */ handle_t p0, 
    	/* Stack Offset: 8 */ [In, Out] /* FC_BIND_CONTEXT */ handle_t* p1
    );

    HRESULT GetSessionReport(
    	/* Stack Offset: 0 */ handle_t p0, 
    	/* Stack Offset: 8 */ [In] /* FC_BIND_CONTEXT */ handle_t* p1, 
    	/* Stack Offset: 16 */ [Out] /* C:(FC_TOP_LEVEL_CONFORMANCE)(24)(FC_DEREFERENCE)(FC_ULONG)(0) */ sbyte[]* p2, 
    	/* Stack Offset: 24 */ [Out] int* p3
    );

    HRESULT GetRuntimeReport(
    	/* Stack Offset: 0 */ handle_t p0, 
    	/* Stack Offset: 8 */ [In] /* FC_BIND_CONTEXT */ handle_t* p1, 
    	/* Stack Offset: 16 */ [In] struct Struct_0* p2, 
    	/* Stack Offset: 24 */ [Out] /* C:(FC_TOP_LEVEL_CONFORMANCE)(32)(FC_DEREFERENCE)(FC_ULONG)(0) */ sbyte[]* p3, 
    	/* Stack Offset: 32 */ [Out] int* p4
    );

    HRESULT GetSessionCertificate(
    	/* Stack Offset: 0 */ handle_t p0, 
    	/* Stack Offset: 8 */ [In] /* FC_BIND_CONTEXT */ handle_t* p1, 
    	/* Stack Offset: 16 */ [Out] /* C:(FC_TOP_LEVEL_CONFORMANCE)(24)(FC_DEREFERENCE)(FC_ULONG)(0) */ sbyte[]* p2, 
    	/* Stack Offset: 24 */ [Out] int* p3
    );
}
```