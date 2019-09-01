import ctypes
import binascii 
import struct
import logging
import json
import inspect
from collections import namedtuple
from ctypes import Array, Structure, Union, _Pointer, _SimpleCData
from json import JSONEncoder

# IDA libraries
import idaapi
import idc

from PyQt5 import QtCore, QtWidgets, QtGui

# IDA API retrocompatibility
if idaapi.IDA_SDK_VERSION <= 695:
    from idaapi import get_segm_qty, getnseg
if idaapi.IDA_SDK_VERSION >= 700:
    from ida_segment import get_segm_qty, getnseg
    import ida_typeinf
else:
    pass



# we can't use ctypes.c_voidp since it rely on Python engine's arch, not the curent PE arch.
POINTER = ( ctypes.c_uint32, ctypes.c_uint64 )[idaapi.get_inf_structure().is_64bit()]
POINTER_SIZE = ctypes.sizeof(POINTER)
READ_PTR_VALUE = (ida_bytes.get_32bit, ida_bytes.get_64bit) [idaapi.get_inf_structure().is_64bit()]

#################################
## ctypes to JSON encoder, copied from https://github.com/rinatz/ctypes_json

class CDataJSONEncoder(JSONEncoder):
    def default(self, obj):

        if hasattr(obj, "_json_serialize"):
            return obj._json_serialize()

        if isinstance(obj, (Array, list)):
            return [self.default(e) for e in obj]

        if isinstance(obj, _Pointer):
            return self.default(obj.contents) if obj else None

        if isinstance(obj, _SimpleCData):
            return self.default(obj.value)

        if isinstance(obj, (bool, int, float, str, long)):
            return obj

        if obj is None:
            return obj

        if isinstance(obj, (Structure, Union)):
            result = {}
            anonymous = getattr(obj, '_anonymous_', [])

            for key, value in getattr(obj, '_fields_', []):
                value = getattr(obj, key)

                # private fields don't encode
                if key.startswith('_'):
                    continue

                if key in anonymous:
                    result.update(self.default(value))
                else:
                    result[key] = self.default(value)

            return result

        return JSONEncoder.default(self, obj)

#################################
## ctypes rpc structures
class RpcStructure(ctypes.Structure):

    @classmethod
    def get_c_instance_name(cls, name):
        """ return a standard name for the extracted C struct instance """

        instance_name = getattr(cls, "__instance_name__")
        return "{name:s}_{instance:s}".format(
            name = name,
            instance = instance_name
        )

    @classmethod
    def get_c_instance_pointer(cls, name, address):
        """ return a standard name for the extracted C struct instance pointer """
        
        if not address:
            return "NULL"

        return "&%s" % cls.get_c_instance_name(name)


    @classmethod
    def generate_format_string_offsets_table(cls, name, fso_ea, handlers_count = 0):

        result = ""

        # Format string offsets
        format_string_offset_pointer = "NULL"
        if not fso_ea or not handlers_count:
            return format_string_offset_pointer, result

        format_string_offset_name = "%s_format_string_offset" % cls.get_c_instance_name(name)
        format_string_offset_pointer = "&%s" % format_string_offset_name

        offsets = [ ida_bytes.get_word(fso_ea + 2*i) for i in range(handlers_count)]
        fso_instance = "static const unsigned short {name:s}[] = {{{values:s}}};".format(
            name =  format_string_offset_name,
            values = ",".join(["0x%04x" % x for x in offsets])
        )

        result += fso_instance
        result += "\n\n"
        return format_string_offset_pointer, result


    @classmethod
    def generate_transfer_syntax_instance(cls, name, transfer_syntax):

        result = ""

        transfer_syntax_pointer = "NULL"
        if not transfer_syntax:
            return transfer_syntax_pointer, result
            
        transfer_syntax_struct_name = "%s_transfer_syntax" % cls.get_c_instance_name(name);
        transfer_syntax_pointer = "&%s" % transfer_syntax_struct_name

        transfer_syntax_struct = "\n".join([
            "static const RPC_SYNTAX_IDENTIFIER %s = %s;" % (
                transfer_syntax_struct_name,
                transfer_syntax.gen_c_struct()
            ),
            "",
            ""
        ])

        result += transfer_syntax_struct
        return transfer_syntax_pointer, result

    @classmethod
    def generate_proc_string_instance(cls, name, proc_string_ea, bytes_read):
        
        result = ""
        proc_string_pointer = "NULL"
        
        if not proc_string_ea:
            return proc_string_pointer, result

        proc_string_name = "%s_proc_string" % cls.get_c_instance_name(name)
        proc_string_pointer  = "&%s" % proc_string_name

        raw_buffer = [ord(x) for x in ida_bytes.get_many_bytes(proc_string_ea, bytes_read)]

        ps_instance = "static const unsigned char {name:s}[] = {{{values:s}}};".format(
            name =  proc_string_name,
            values = ",".join(["0x%02x" % x for x in raw_buffer])
        )

        result += ps_instance
        result += "\n\n"
        return proc_string_pointer, result


class GUID(RpcStructure):
    _fields_ = [
        ('Data1',  ctypes.c_uint),
        ('Data2',  ctypes.c_ushort),
        ('Data3',  ctypes.c_ushort),
        ('Data4',  ctypes.c_ubyte * 8),
    ]

    def __eq__(self, other):
        return  self.Data1 == other.Data1 and \
                self.Data2 == other.Data2 and \
                self.Data3 == other.Data3 and \
                all( x == y  for x, y in zip(self.Data4, other.Data4))

    def __str__(self):
        return "%04x-%02x-%02x-%s" % (
                self.Data1, 
                self.Data2, 
                self.Data3, 
                b"".join("%02x" % x for x in self.Data4)
        )

    def gen_c_struct(self):
        return "{0x%x, 0x%x, 0x%x, %s}" % (
            self.Data1, 
            self.Data2, 
            self.Data3, 
            "{ %s }" % b", ".join("0x%02x" % x for x in self.Data4)
        )

    def _json_serialize(self):
        """
        Return the GUID in a way Microsoft likes.
        """

        return "%08x-%04x-%04x-%04x-%s" % (
                self.Data1, 
                self.Data2, 
                self.Data3, 
                self.Data4[0]*256 + self.Data4[1], 
                b"".join("%02x" % x for x in self.Data4[2:])
        )

    @classmethod
    def from_guid_string(cls, guid_string):

        if guid_string.count('-') == 3:
            # "%04x-%02x-%02x-%s" GUID style
            hexData1, hexData2, hexData3, hexData4 = guid_string.split('-')
            
            Data1 = int(hexData1, 16)
            Data2 = int(hexData2, 16)
            Data3 = int(hexData3, 16)
            Data4 = [int(hexData4[i:i+2], 16) for i in range(0, len(hexData4), 2)]

            return cls(Data1, Data2, Data3, (ctypes.c_ubyte*8)(*Data4))

        elif guid_string.count('-') == 4:
            # "%04x-%02x-%02x-%02x-%s" GUID style
            hexData1, hexData2, hexData3, hexData4Hi, hexData4 = guid_string.split('-')

            Data4Hi = int(hexData4Hi, 16)
            
            Data1 = int(hexData1, 16)
            Data2 = int(hexData2, 16)
            Data3 = int(hexData3, 16)
            Data4 = [Data4Hi >> 8, Data4Hi & 0xff] + [int(hexData4[i:i+2], 16) for i in range(0, len(hexData4), 2)]

            return cls(Data1, Data2, Data3, (ctypes.c_ubyte*8)(*Data4))
        else:
            raise ValueError("Unrecognized GUID format string : %s" % guid_string)


class RPC_VERSION(RpcStructure):
    _fields_ = [
        ('MajorVersion', ctypes.c_ushort),
        ('MinorVersion', ctypes.c_ushort),
    ]

    def __str__(self):
        return "%d.%d" % (self.MajorVersion, self.MinorVersion)

    def gen_c_struct(self):
        return "{%d, %d}" % (self.MajorVersion, self.MinorVersion)

    def __eq__ (self, other):
        return  self.MajorVersion == other.MajorVersion and \
                self.MinorVersion == other.MinorVersion

class RPC_SYNTAX_IDENTIFIER(RpcStructure):

    _fields_ = [
        ('SyntaxGUID', GUID),
        ('SyntaxVersion', RPC_VERSION),
    ]

    def __eq__ (self, other):
        return  self.SyntaxGUID == other.SyntaxGUID and \
                self.SyntaxVersion == other.SyntaxVersion

    def gen_c_struct(self):
        return "{%s, %s}" % (self.SyntaxGUID.gen_c_struct(), self.SyntaxVersion.gen_c_struct())

    def __str__(self):
        if self == DCE_TransferSyntax:
            return "DCE syntax (%s)" % (self.SyntaxVersion)
        elif self == NDR64_TransferSyntax:
            return "NDR64 syntax (%s)" % (self.SyntaxVersion)
        else:
            return "%s (%s)"   % (self.SyntaxGUID, self.SyntaxVersion)


# Well-known UUID constants
DCE_TransferSyntax = RPC_SYNTAX_IDENTIFIER(GUID.from_guid_string("8A885D04-1CEB-11C9-9FE8-08002B104860"), (2, 0))
NDR64_TransferSyntax = RPC_SYNTAX_IDENTIFIER(GUID.from_guid_string("71710533-BEBA-4937-8319-B5DBEF9CCC36"), (1, 0))




class RPC_SERVER_INTERFACE(RpcStructure):
    _pack_ = POINTER_SIZE
    _fields_ = [
        ('Length', ctypes.c_uint),
        ('InterfaceId', RPC_SYNTAX_IDENTIFIER),
        ('TransferSyntax', RPC_SYNTAX_IDENTIFIER),
        ('DispatchTable', POINTER),
        ('RpcProtseqEndpointCount', ctypes.c_uint),
        ('RpcProtseqEndpoint', POINTER),
        ('DefaultManagerEpv', POINTER),
        ('InterpreterInfo', POINTER),
        ('Flags', ctypes.c_uint),
    ]

    __instance_name__ = "interface"

    def gen_c_struct(self, name, fa, is_client = False):

        result = ""
        struct_name = ("RPC_SERVER_INTERFACE", "RPC_CLIENT_INTERFACE")[is_client]

        dispatch_table_pointer = "NULL"
        if self.DispatchTable:
            dispatch_table_pointer = "&%s_dispatch_table" % name

        interpreter_info_pointer = "NULL"
        if self.InterpreterInfo:
            interpreter_info_pointer = "&%s_interpreter_info" % name


        interface_struct = "\n".join([
            "static const %s %s = {" % (struct_name, RPC_SERVER_INTERFACE.get_c_instance_name(name)),
            "   .Length = sizeof(%s)," % struct_name,
            "   .InterfaceId = %s," % self.InterfaceId.gen_c_struct(),
            "   .TransferSyntax = %s," % self.TransferSyntax.gen_c_struct(),
            "   .DispatchTable = %s," % dispatch_table_pointer,
            "   .RpcProtseqEndpointCount : %d," % self.RpcProtseqEndpointCount,
            "   .RpcProtseqEndpoint : NULL, // FIXME", # % self.RpcProtseqEndpoint,
            "   .DefaultManagerEpv : NULL, // FIXME", # % self.DefaultManagerEpv,
            "   .InterpreterInfo : %s,"  % interpreter_info_pointer,
            "   .Flags : 0x%x" % self.Flags,
            "};",
            "",
            ""
        ])

        result += interface_struct
        
        return result

    def has_proxy_info(self):

        # TODO : 0x6000000 is an undocumented flag indicating that InterpreterInfo 
        # is a stubless proxy structure, not a fully defined MIDL_SERVER_INFO instance.
        # TODO :  self.Flags == 0  can also means "inlined" server with no interpretor info
        return (self.Flags & 0x2000000) == 0x2000000

    def has_interpreter_info(self):
        return (self.Flags & 0x4000000) == 0x4000000


    def __str__(self):
        return "\n".join([
            " -Length : %d" % self.Length,
            " -InterfaceId : %s" % self.InterfaceId,
            " -TransferSyntax : %s" % self.TransferSyntax,
            " -DispatchTable : 0x%x" % self.DispatchTable,
            " -RpcProtseqEndpointCount : %d" % self.RpcProtseqEndpointCount,
            " -RpcProtseqEndpoint : 0x%x" % self.RpcProtseqEndpoint,
            " -DefaultManagerEpv : 0x%x" % self.DefaultManagerEpv,
            " -InterpreterInfo : 0x%x" % self.InterpreterInfo,
            " -Flags : 0x%x" % self.Flags
        ])

class MIDL_SERVER_INFO(RpcStructure):
    
    _fields_ = [
        ('pStubDesc', POINTER),         # MIDL_STUB_DESC
        ('DispatchTable', POINTER),
        ('ProcString', POINTER),
        ('FmtStringOffset', POINTER),
        ('ThunkTable', POINTER),
        ('pTransferSyntax', POINTER),
        ('nCount', POINTER),
        ('pSyntaxInfo', POINTER),       # MIDL_SYNTAX_INFO
    ]

    __instance_name__ = "interpreter_info"

    def __str__(self):
        return "\n".join([
            " -pStubDesc : 0x%x" % self.pStubDesc,
            " -DispatchTable : 0x%x" % self.DispatchTable,
            " -ProcString : 0x%x" % self.ProcString,
            " -FmtStringOffset : 0x%x" % self.FmtStringOffset,
            " -ThunkTable : 0x%x" % self.ThunkTable,
            " -pTransferSyntax : 0x%x" % self.pTransferSyntax,
            " -nCount : %d" % self.nCount,
            " -pSyntaxInfo : 0x%x" % self.pSyntaxInfo,
        ])

    def gen_c_struct(self, name, fa, bytes_read = 0x100):

        result = ""
        dispatch_table_functions_pointer = "NULL"

        query_fa_result = list(filter(lambda r: r.stub_desc.address == self.pStubDesc, fa.results))[0]
        proc_handlers_ea = list(query_fa_result.get_proc_handlers())

        # Dispatch table
        if len(proc_handlers_ea):

            # Read dispatch table functions names, or generate fun_xxx if not
            rpc_dispatch_functions = [idaapi.get_name(ea) for ea in proc_handlers_ea]
            rpc_dispatch_functions = "\n   ".join(["%s," % fun for fun in rpc_dispatch_functions])
            
            # generate a function pointer table for it
            dispatch_table_functions_instance =  "\n".join([
                "static const SERVER_ROUTINE %s_routine_table[] = {" % MIDL_SERVER_INFO.get_c_instance_name(name),
                "   %s" % rpc_dispatch_functions,
                "   NULL",
                "};",
                "",
                ""
            ])

            dispatch_table_functions_pointer = "&%s_routine_table" % MIDL_SERVER_INFO.get_c_instance_name(name)
            result += dispatch_table_functions_instance

        # Format string offsets
        format_string_offset_pointer, fso_instance = MIDL_SERVER_INFO.generate_format_string_offsets_table(name, self.FmtStringOffset, len(proc_handlers_ea))
        result += fso_instance

        # Proc string
        proc_string_pointer, ps_instance = MIDL_SERVER_INFO.generate_proc_string_instance(name, self.ProcString, bytes_read)
        result += ps_instance

        # transfer syntax
        transfer_syntax_object = fa.query_rpc_struct(self.pTransferSyntax)
        transfer_syntax_pointer, ts_instance = MIDL_SERVER_INFO.generate_transfer_syntax_instance(name, transfer_syntax_object)
        result += ts_instance


        midl_server_instance = "\n".join([
            "static const MIDL_SERVER_INFO %s = {" % MIDL_SERVER_INFO.get_c_instance_name(name),
            "   .pStubDesc = {stub_desc:s},".format(stub_desc=MIDL_STUB_DESC.get_c_instance_pointer(name, self.pStubDesc)),
            "   .DispatchTable = {dp:s},".format(dp = dispatch_table_functions_pointer),
            "   .FmtStringOffset = %s," % format_string_offset_pointer,
            "   .ProcString = %s," % proc_string_pointer,
            "   .ThunkTable = NULL, // FIXME",
            "   .pTransferSyntax = %s," % transfer_syntax_pointer,
            "   .nCount={c:d},".format(c = self.nCount),
            "   .pSyntaxInfo = NULL //FIXME",
            "};",
            "",
            ""
        ])
        result += midl_server_instance
        return result;


class MIDL_STUBLESS_PROXY_INFO(RpcStructure):
    
    _fields_ = [
        ('pStubDesc', POINTER),         # MIDL_STUB_DESC
        ('ProcString', POINTER),
        ('FmtStringOffset', POINTER),
        ('pTransferSyntax', POINTER),
        ('nCount', POINTER),
        ('pSyntaxInfo', POINTER),       # MIDL_SYNTAX_INFO
    ]

    __instance_name__ = "interpreter_info"

    def __str__(self):
        return "\n".join([
            " -pStubDesc : 0x%x" % self.pStubDesc,
            " -ProcString : 0x%x" % self.ProcString,
            " -FmtStringOffset : 0x%x" % self.FmtStringOffset,
            " -pTransferSyntax : 0x%x" % self.pTransferSyntax,
            " -nCount : %d" % self.nCount,
            " -pSyntaxInfo : 0x%x" % self.pSyntaxInfo
        ])

    def gen_c_struct(self, name, fa, bytes_read = None):

        result = ""

        stub_desc_pointer = MIDL_STUB_DESC.get_c_instance_pointer(name, self.pStubDesc)


        # Proc string
        proc_string_pointer, ps_instance = MIDL_SERVER_INFO.generate_proc_string_instance(name, self.ProcString, bytes_read)
        result += ps_instance

        # transfer syntax
        transfer_syntax_object = fa.query_rpc_struct(self.pTransferSyntax)
        transfer_syntax_pointer, ts_instance = MIDL_SERVER_INFO.generate_transfer_syntax_instance(name, transfer_syntax_object)
        result += ts_instance

        # we have no way to know how many proc handlers are defined from the client side,
        # so we go overboard
        format_string_offset_pointer, fso_instance = MIDL_SERVER_INFO.generate_format_string_offsets_table(name, self.FmtStringOffset, bytes_read/2)
        result += fso_instance

        interpreter_struct = "\n".join([
            "static const MIDL_STUBLESS_PROXY_INFO %s_interpreter_info = {" % (name),
            "   .pStubDesc = %s," % stub_desc_pointer,
            "   .FmtStringOffset = %s," % format_string_offset_pointer,
            "   .ProcString = %s," % proc_string_pointer,
            "   .pTransferSyntax = %s," % transfer_syntax_pointer,
            "   .nCount = %d," % self.nCount,
            "   .pSyntaxInfo = NULL, // FIXME", # % 
            "};",
            "",
            ""
        ])

        result += interpreter_struct
        return result

class RPC_DISPATCH_TABLE(RpcStructure):
    _pack_ = POINTER_SIZE
    _fields_ = [
        ('DispatchTableCount', ctypes.c_uint),
        ('DispatchTable', POINTER),
        ('Reserved', POINTER),
    ]
    __instance_name__ = "dispatch_table"

    def __str__(self):
        return "\n".join([
            " -DispatchTableCount : %d" % self.DispatchTableCount,
            " -DispatchTable : 0x%x" % self.DispatchTable
        ])

    def gen_c_struct(self, name, fa):

        result = ""
        dispatch_table_functions_pointer = "NULL"

        if self.DispatchTableCount:

            # Read dispatch table functions names (usually NdrServerCall/NdrClientCall or NdrAsyncServerCall/NdrAsyncClientCall)
            rpc_dispatch_functions_ea =  [ self.DispatchTable + ph_ea*POINTER_SIZE for ph_ea in range(0, self.DispatchTableCount)]
            rpc_dispatch_functions = [idaapi.get_name(READ_PTR_VALUE(ea)) for ea in rpc_dispatch_functions_ea]
            rpc_dispatch_functions = "\n   ".join(["%s," % fun for fun in rpc_dispatch_functions])
            
            # generate a function pointer table for it
            dispatch_table_functions_instance =  "\n".join([
                "static const RPC_DISPATCH_FUNCTION %s_table[] = {" % RPC_DISPATCH_TABLE.get_c_instance_name(name),
                "   %s" % rpc_dispatch_functions,
                "   NULL",
                "};",
                "",
                ""
            ])

            dispatch_table_functions_pointer = "&%s_table" % RPC_DISPATCH_TABLE.get_c_instance_name(name)
            result += dispatch_table_functions_instance
            

        dispatch_table_instance =  "\n".join([
            "static const RPC_DISPATCH_TABLE {instance:s} = {{".format(instance = RPC_DISPATCH_TABLE.get_c_instance_name(name)),
            "   .DispatchTableCount = {count:d},".format(count = self.DispatchTableCount),
            "   .DispatchTable = (RPC_DISPATCH_FUNCTION*) {dispatch_table_ptr:s}".format(dispatch_table_ptr = dispatch_table_functions_pointer),
            "};",
            "",
            ""
        ])

        result += dispatch_table_instance
        return result

class MIDL_STUB_DESC(RpcStructure):
    _pack_ = POINTER_SIZE
    _fields_ = [
        ('RpcInterfaceInformation', POINTER),
        ('pfnAllocate', POINTER),
        ('pfnFree', POINTER),
        ('pAutoHandle', POINTER), # TODO : correctly implement the union

        ('apfnNdrRundownRoutines',  POINTER),       # const NDR_RUNDOWN
        ('aGenericBindingRoutinePairs',  POINTER),  # const GENERIC_BINDING_ROUTINE_PAIR
        ('apfnExprEval',  POINTER),                 # const EXPR_EVAL
        ('aXmitQuintuple',  POINTER),               # const XMIT_ROUTINE_QUINTUPLE
        ('pFormatTypes',  POINTER),                 # unsigned char *
        ('fCheckBounds', ctypes.c_int),
        ('Version', ctypes.c_ulong),
        ('pMallocFreeStruct',  POINTER),            # MALLOC_FREE_STRUCT
        ('MIDLVersion', ctypes.c_long),
        ('CommFaultOffsets',  POINTER),             # const COMM_FAULT_OFFSETS
        ('aUserMarshalQuadruple',  POINTER),        # const USER_MARSHAL_ROUTINE_QUADRUPLE
        ('NotifyRoutineTable',  POINTER),           # const NDR_NOTIFY_ROUTINE
        ('mFlags',  POINTER),
        ('CsRoutineTables',  POINTER),              # const NDR_CS_ROUTINES
        ('ProxyServerInfo',  POINTER),
        ('pExprInfo',  POINTER),                    # const NDR_EXPR_DESC
    ]
    __instance_name__ = "stub_desc"

    def __str__(self):
        return "\n".join([
            " -RpcInterfaceInformation : 0x%x" % self.RpcInterfaceInformation,
            " -pfnAllocate : 0x%x" % self.pfnAllocate,
            " -pfnFree : 0x%x" % self.pfnFree,
            " -pFormatTypes : 0x%x" % self.pFormatTypes,
            " -Version : 0x%x" % self.Version,
            " -MIDLVersion : 0x%x" % self.MIDLVersion,
            " -mFlags : 0x%x" % self.mFlags,
            " -ProxyServerInfo : 0x%x" % self.ProxyServerInfo,
            " -pExprInfo : 0x%x" % self.pExprInfo
        ])

    def gen_c_struct(self, name, fa):
        return "\n".join([
            "static const MIDL_STUB_DESC %s = {" % MIDL_STUB_DESC.get_c_instance_name(name),
            "    .RpcInterfaceInformation = {interface:s},".format(interface = RPC_SERVER_INTERFACE.get_c_instance_pointer(name, self.RpcInterfaceInformation)),
            "    .pfnAllocate = MIDL_user_allocate,",
            "    .pfnFree = MIDL_user_free,",
            "    // FIXME",
            "    .fCheckBounds : %d," % self.fCheckBounds,
            "    .Version : 0x%x," % self.Version,
            "    // FIXME",
            "    .MIDLVersion : 0x%x," % self.MIDLVersion,
            "    // FIXME",
            "    .mFlags : 0x%x," % self.mFlags,
            "    // FIXME",
            "};",
            "",
            ""
        ])

class MIDL_SYNTAX_INFO(RpcStructure):
    _pack_ = POINTER_SIZE
    _fields_ = [
        ('TransferSyntax', RPC_SYNTAX_IDENTIFIER),
        ('DispatchTable', POINTER),                 # RPC_DISPATCH_TABLE
        ('ProcString', POINTER),
        ('FmtStringOffset', POINTER),
        ('TypeString', POINTER),
        ('aUserMarshalQuadruple', POINTER),
        ('pMethodProperties', POINTER),             # MIDL_INTERFACE_METHOD_PROPERTIES
        ('pReserved2', POINTER),
    ]
    __instance_name__ = "syntax_info"

    def __str__(self):
        return "\n".join([
            " -TransferSyntax : %s" % self.TransferSyntax,
            " -DispatchTable : 0x%x" % self.DispatchTable,
            " -ProcString : 0x%x" % self.ProcString,
            " -FmtStringOffset : 0x%x" % self.FmtStringOffset
        ])

    def gen_c_struct(self, name, fa):
        result += ""

        return "\n".join([
            "static const MIDL_SYNTAX_INFO %s = {" % MIDL_SYNTAX_INFO.get_c_instance_name(name),
            "    .TransferSyntax={syntax:s},".format(syntax = self.TransferSyntax.gen_c_struct()),
            "};",
            "",
            ""
        ])

#################################
## results view

# translation between rpc struct type and it's IDA name
TYPE_RPC_SERVER_INTERFACE       =    "_RPC_SERVER_INTERFACE"
TYPE_MIDL_STUB_DESC             =    "_MIDL_STUB_DESC"
TYPE_MIDL_SYNTAX_INFO           =    "_MIDL_SYNTAX_INFO"
TYPE_MIDL_SERVER_INFO           =    "_MIDL_SERVER_INFO_"
TYPE_MIDL_STUBLESS_PROXY_INFO   =    "MIDL_STUBLESS_PROXY_INFO"
TYPE_RPC_SYNTAX_IDENTIFIER      =    "RPC_SYNTAX_IDENTIFIER"
TYPE_RPC_DISPATCH_TABLE         =    "RPC_DISPATCH_TABLE"

class CancelTypingForm(Form):
    s = """ LOL

    Hey, this guy wants to cancel its changes.
    'Might as well ask for an "undo" button in IDA !
    (This joke got stale with IDA 7.3 -_-)
    """

    def __init__(self):
        Form.__init__(self, CancelTypingForm.s ,{})


class RpcResultsModel(QtCore.QAbstractTableModel):
    
    COL_SYNTAX_GUID = 0x00
    COL_RPC_TYPE = 0x01
    COL_ADDRESS = 0x02
    COL_DESCRIPTION = 0x03
    COL_EMPTY = 0x04

    SAMPLE_CONTENTS = [
        'XXXXXXXX-YYYY-ZZZZ-TTTTTTTTTT',
        'MIDL_STUBLESS_PROXY_INFO',
        '0xcafebabe',
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    ]
    
    def __init__(self, rpc_endpoints, parent=None):
        super(RpcResultsModel, self).__init__(parent)

        #----------------------------------------------------------------------
        # Headers
        #----------------------------------------------------------------------

        self._column_headers = {
            RpcResultsModel.COL_SYNTAX_GUID : 'GUID',
            RpcResultsModel.COL_RPC_TYPE : 'Object type',
            RpcResultsModel.COL_ADDRESS : 'Address',
            RpcResultsModel.COL_DESCRIPTION : 'Description'
        }

        #----------------------------------------------------------------------
        # UI
        #----------------------------------------------------------------------

        self._font = QtGui.QFont("Monospace")
        self._font.setStyleHint(QtGui.QFont.TypeWriter)

        #----------------------------------------------------------------------
        # Data store
        #----------------------------------------------------------------------

        self._results = list(rpc_endpoints)
        self._row_count = len(self._results)


    def flags(self, index):
        return QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

    def rowCount(self, index=QtCore.QModelIndex()):
        """
        The number of table rows.
        """
        return self._row_count

    def columnCount(self, index=QtCore.QModelIndex()):
        """
        The number of table columns.
        """
        return len(self._column_headers)

    def headerData(self, column, orientation, role=QtCore.Qt.DisplayRole):
        """
        Define the properties of the the table rows & columns.
        """

        if orientation == QtCore.Qt.Horizontal:

            # the title of the header columns has been requested
            if role == QtCore.Qt.DisplayRole:
                try:
                    return self._column_headers[column]
                except KeyError as e:
                    pass

            # the text alignment of the header has beeen requested
            elif role == QtCore.Qt.TextAlignmentRole:

                # center align all columns
                return QtCore.Qt.AlignHCenter

        # unhandled header request
        return None

    def data(self, index, role=QtCore.Qt.DisplayRole):
        """
        Define how Qt should access the underlying model data.
        """

        # data display request
        if role == QtCore.Qt.DisplayRole:

            # grab for speed
            row = index.row()
            column = index.column()

            if column == RpcResultsModel.COL_SYNTAX_GUID:
                return str(self._results[row].IID.get_syntax_guid())
            elif column == RpcResultsModel.COL_RPC_TYPE:
                return self._results[row].type
            elif column == RpcResultsModel.COL_ADDRESS:
                return "0x%x" % self._results[row].address
            elif column == RpcResultsModel.COL_DESCRIPTION:
                return str(self._results[row])

        # font color request
        elif role == QtCore.Qt.ForegroundRole:
            return QtGui.QColor(QtCore.Qt.black)

        # font format request
        elif role == QtCore.Qt.FontRole:
            return self._font

        # text alignment request
        elif role == QtCore.Qt.TextAlignmentRole:
            column = index.column()
            return (
                QtCore.Qt.AlignLeft, 
                QtCore.Qt.AlignLeft, 
                QtCore.Qt.AlignHCenter, 
                QtCore.Qt.AlignLeft
            )[column]

        # unhandeled request, nothing to do
        return None


class RpcResultsForm( idaapi.PluginForm ):

    def __init__(self, _rpc_endpoints):

        super(RpcResultsForm, self).__init__()
        self._rpc_endpoints = _rpc_endpoints
    
    def OnCreate(self, form):
        """
        Initialize the custom PyQt5 content on form creation.
        """

        # Get parent widget
        self._widget  = self.FormToPyQtWidget(form)

        self._init_ui()

    def show(self):
        """
        Make the created form visible as a tabbed view.
        """
        flags = idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WOPN_PERSIST 
        return idaapi.PluginForm.Show(self, "detected rpc strcutures", flags)

    
    def _init_ui(self):
        self._font = QtGui.QFont("Monospace")
        self._font.setStyleHint(QtGui.QFont.TypeWriter)
        self._font_metrics = QtGui.QFontMetricsF(self._font)

        self._model = RpcResultsModel(self._rpc_endpoints, self._widget)
        self._table = QtWidgets.QTableView()
        self._table.setStyleSheet(
            "QTableView { gridline-color: white; background-color: white } "  +
            "QTableView::item:selected { color: grey; background-color: lightblue; } "
        )

        # set these properties so the user can arbitrarily shrink the table
        self._table.setMinimumHeight(0)
        self._table.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Ignored
        )

        self._table.setModel(self._model)

        # jump to disassembly on table row double click
        self._table.doubleClicked.connect(self._ui_entry_double_click)

        # right click popup menu
        self._table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._ui_ctx_menu_handler)

        self._action_apply_type = QtWidgets.QAction("Apply type", None)
        self._action_clear_type = QtWidgets.QAction("Clear applied type", None)
        self._action_rename_struct = QtWidgets.QAction("Renamed applied type", None)
        self._action_rename_proc_handlers = QtWidgets.QAction("Renamed proc handlers", None)

        # set the initial column widths for the table
        self._guess_column_width()

        # table selection should be by row, not by cell
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # more code-friendly, readable aliases
        vh = self._table.verticalHeader()
        hh = self._table.horizontalHeader()
        vh.setSectionResizeMode(QtWidgets.QHeaderView.Fixed)

        # hide the vertical header themselves as we don't need them
        vh.hide()

        # stretch the last column (which is blank)
        hh.setStretchLastSection(True)

        # Allow multiline cells
        self._table.setWordWrap(True) 
        self._table.setTextElideMode(QtCore.Qt.ElideMiddle);
        self._table.resizeColumnsToContents()
        self._table.resizeRowsToContents()

        layout = QtWidgets.QGridLayout()
        layout.addWidget(self._table)
        self._widget.setLayout(layout)



    def _guess_column_width(self):
        """
        Initial column redimensionning based on "hints" (sample values)
        """

        for i in xrange(len(self._model.__class__.SAMPLE_CONTENTS)):
            sample_width = self._font_metrics.boundingRect(self._model.__class__.SAMPLE_CONTENTS[i]).width()
            header_width = self._font_metrics.boundingRect(self._model._column_headers[i]).width()

            self._table.setColumnWidth(i, max(header_width, sample_width))

    def _ui_entry_double_click(self, index):
        """
        Handle double click event on the coverage table.
        A double click on the coverage table view will jump the user to
        the corresponding function in the IDA disassembly view.
        """
        idaapi.jumpto(self._model._results[index.row()].address)

    def _ui_ctx_menu_handler(self, position):
        """
        Handle right click context menu event on the coverage table.
        """

        # create a right click menu based on the state and context
        ctx_menu = self._populate_ctx_menu()
        if not ctx_menu:
            return

        # show the popup menu to the user, and wait for their selection
        action = ctx_menu.exec_(self._table.viewport().mapToGlobal(position))

        # process the user action
        self._process_ctx_menu_action(action)

    def _populate_ctx_menu(self):
        """
        Populate a context menu for the table view based on selection.
        Returns a populated QMenu, or None.
        """

        # get the list rows currently selected in the coverage table
        selected_rows = self._table.selectionModel().selectedRows()
        if len(selected_rows) == 0:
            return None

        # the context menu we will dynamically populate
        ctx_menu = QtWidgets.QMenu()

    
        ctx_menu.addAction(self._action_apply_type)
        ctx_menu.addAction(self._action_clear_type)
        ctx_menu.addSeparator()

        ctx_menu.addAction(self._action_rename_struct)

        if (len(selected_rows) == 1):
            item = self._model._results[selected_rows[0].row()]

            if item.IID.get_proc_handlers():
                ctx_menu.addSeparator()
                ctx_menu.addAction(self._action_rename_proc_handlers)


        # return the completed context menu
        return ctx_menu

    def _process_ctx_menu_action(self, action):
        """
        Process the given (user selected) context menu action.
        """

        # a right click menu action was not clicked. nothing else to do
        if not action:
            return

        # get the list rows currently selected in the coverage table
        selected_rows = self._table.selectionModel().selectedRows()
        if len(selected_rows) == 0:
            return

        for row in selected_rows:
            row_n = row.row()
            result = self._model._results[row_n]

            
            if action == self._action_apply_type:
                success = MakeStructEx(result.address, -1, result.type)
                print("[findrpc] Applying type %s at address 0x%x : %s" % (result.type, result.address, ("KO", "OK")[success]))
                if not success:
                    warning("Could not apply type via idapython. Do it by hand instead (Alt+Q > %s)" % result.type)

            # handle the 'Copy name' action
            elif action == self._action_clear_type:
                #logging.debug("Clearing applied types to selected lines to item %d" % row_n)
                f = CancelTypingForm()
                f, args = f.Compile()
                ok = f.Execute()

            elif action == self._action_rename_struct:
                chosen_name = "_findrpc_{iid:s}_{type:s}".format(
                    iid = str(result.IID.interface.object.InterfaceId.SyntaxGUID).replace('-', '_'), 
                    type = str(result.type).lower()
                )
                print("[findrpc] renaming address 0x%x to %s" % (result.address, chosen_name))
                idc.MakeName(result.address, chosen_name)

            elif action == self._action_rename_proc_handlers:

                for i, proc_handler_ea in enumerate(result.IID.get_proc_handlers()):
                    chosen_name = "_findrpc_{iid:s}_proc_handler_{index:d}".format(
                        iid = str(result.IID.interface.object.InterfaceId.SyntaxGUID).replace('-', '_'), 
                        index = i
                    )
                    print("[findrpc] renaming address 0x%x to %s" % (proc_handler_ea, chosen_name))
                    idc.MakeName(proc_handler_ea, chosen_name)


class FindRpcResultsModel(QtCore.QAbstractTableModel):
    
    COL_SYNTAX_GUID = 0x00
    COL_RPC_TYPE = 0x01
    COL_DISPATCH_TABLE = 0x02
    COL_PROC_HANDLERS = 0x03
    COL_ADDITIONAL_INFOS = 0x04

    SAMPLE_CONTENTS = [
        'XXXXXXXX-YYYY-ZZZZ-TTTTTTTTTT',
        'server',
        '0xcafebabe',
        '0xcafebabe',
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    ]

    def __init__(self, rpc_results, parent=None):
        super(FindRpcResultsModel, self).__init__(parent)

        #----------------------------------------------------------------------
        # Headers
        #----------------------------------------------------------------------
        self._column_headers = {
            FindRpcResultsModel.COL_SYNTAX_GUID : 'GUID',
            FindRpcResultsModel.COL_RPC_TYPE : 'client/server',
            FindRpcResultsModel.COL_DISPATCH_TABLE : 'Dispatch Table Address',
            FindRpcResultsModel.COL_PROC_HANDLERS : 'Proc Handlers',
            FindRpcResultsModel.COL_ADDITIONAL_INFOS : 'Additionnal infos'
        }

        #----------------------------------------------------------------------
        # UI
        #----------------------------------------------------------------------
        self._font = QtGui.QFont("Monospace")
        self._font.setStyleHint(QtGui.QFont.TypeWriter)

        #----------------------------------------------------------------------
        # Data store
        #----------------------------------------------------------------------
        self._results = list(rpc_results)
        self._row_count = len(self._results)

    def flags(self, index):
        return QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

    def rowCount(self, index=QtCore.QModelIndex()):
        """
        The number of table rows.
        """
        return self._row_count

    def columnCount(self, index=QtCore.QModelIndex()):
        """
        The number of table columns.
        """
        return len(self._column_headers)

    def headerData(self, column, orientation, role=QtCore.Qt.DisplayRole):
        """
        Define the properties of the the table rows & columns.
        """

        if orientation == QtCore.Qt.Horizontal:

            # the title of the header columns has been requested
            if role == QtCore.Qt.DisplayRole:
                try:
                    return self._column_headers[column]
                except KeyError as e:
                    pass

            # the text alignment of the header has beeen requested
            elif role == QtCore.Qt.TextAlignmentRole:

                # center align all columns
                return QtCore.Qt.AlignHCenter

        # unhandled header request
        return None

    def data(self, index, role=QtCore.Qt.DisplayRole):
        """
        Define how Qt should access the underlying model data.
        """

        # data display request
        if role == QtCore.Qt.DisplayRole:

            # grab for speed
            row = index.row()
            column = index.column()

            findrpc_result = self._results[row]

            if column == FindRpcResultsModel.COL_SYNTAX_GUID:
                return str(findrpc_result.get_syntax_guid())
            elif column == FindRpcResultsModel.COL_RPC_TYPE:
                return ("server", "client")[findrpc_result.is_client()]
            elif column == FindRpcResultsModel.COL_DISPATCH_TABLE:
                
                if not findrpc_result.get_proc_handlers_table_ea():
                    return "None"
                return "0x%x" % findrpc_result.get_proc_handlers_table_ea()
            elif column == FindRpcResultsModel.COL_PROC_HANDLERS:

                proc_handlers = findrpc_result.get_proc_handlers()
                if not proc_handlers:
                    return "None"

                str_proc_handlers = [ "-0x%x" % ea for ea in proc_handlers ]
                return "\n".join(str_proc_handlers)

            elif column == FindRpcResultsModel.COL_ADDITIONAL_INFOS:
                return str(self._results[row])

        # font color request
        elif role == QtCore.Qt.ForegroundRole:
            return QtGui.QColor(QtCore.Qt.black)

        # font format request
        elif role == QtCore.Qt.FontRole:
            return self._font

        # text alignment request
        elif role == QtCore.Qt.TextAlignmentRole:
            column = index.column()
            return (QtCore.Qt.AlignLeft, QtCore.Qt.AlignHCenter, QtCore.Qt.AlignHCenter, QtCore.Qt.AlignHCenter,QtCore.Qt.AlignLeft)[column]

        # unhandeled request, nothing to do
        return None

class FindRpcResultsForm( idaapi.PluginForm ):

    def __init__(self, rpc_results_db):

        super(FindRpcResultsForm, self).__init__()
        
        self.rpc_results_db = rpc_results_db
        self.rpc_results = rpc_results_db.results
        self._widget = None
    
    def OnCreate(self, form):
        """
        Initialize the custom PyQt5 content on form creation.
        """

        # Get parent widget
        self._widget = self.FormToPyQtWidget(form)

        self._init_ui()

    def show(self):
        """
        Make the created form visible as a tabbed view.
        """
        flags = idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WOPN_PERSIST 
        return idaapi.PluginForm.Show(self, "FindRpc results", flags)
        

    def _init_ui(self):

        if not self.GetWidget():
            return

        self._font = QtGui.QFont("Monospace")
        self._font.setStyleHint(QtGui.QFont.TypeWriter)
        self._font_metrics = QtGui.QFontMetricsF(self._font)

        self._model = FindRpcResultsModel(self.rpc_results, self._widget)
        self._table = QtWidgets.QTableView()
        self._table.setStyleSheet(
            "QTableView { gridline-color: white; background-color: white } "  +
            "QTableView::item:selected { color: grey; background-color: lightblue; } "
        )

        # set these properties so the user can arbitrarily shrink the table
        self._table.setMinimumHeight(0)
        self._table.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Ignored
        )

        self._table.setModel(self._model)


        # # jump to disassembly on table row double click
        # self._table.doubleClicked.connect(self._ui_entry_double_click)

        # right click popup menu
        self._table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._ui_ctx_menu_handler)

        self._action_generate_stub = QtWidgets.QAction("Generate stub (beta)", None)
        self._action_export_json = QtWidgets.QAction("Generate json summary", None)
        self._action_decompile = QtWidgets.QAction("Decompile interface (only on Windows)", None)
        # self._action_rename_struct = QtWidgets.QAction("Renamed applied type", None)
        # self._action_rename_proc_handlers = QtWidgets.QAction("Renamed proc handlers", None)

        # set the initial column widths for the table
        self._guess_column_width()

        # table selection should be by row, not by cell
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # more code-friendly, readable aliases
        vh = self._table.verticalHeader()
        hh = self._table.horizontalHeader()
        vh.setSectionResizeMode(QtWidgets.QHeaderView.Fixed)

        # hide the vertical header themselves as we don't need them
        vh.hide()

        # stretch the last column (which is blank)
        hh.setStretchLastSection(True)

        # Allow multiline cells
        self._table.setWordWrap(True) 
        self._table.setTextElideMode(QtCore.Qt.ElideMiddle);
        self._table.resizeColumnsToContents()
        self._table.resizeRowsToContents()

        layout = QtWidgets.QGridLayout()
        layout.addWidget(self._table)
        self._widget.setLayout(layout)


    def _guess_column_width(self):
        """
        Initial column redimensionning based on "hints" (sample values)
        """

        for i in xrange(len(self._model.__class__.SAMPLE_CONTENTS)):
            sample_width = self._font_metrics.boundingRect(self._model.__class__.SAMPLE_CONTENTS[i]).width()
            header_width = self._font_metrics.boundingRect(self._model._column_headers[i]).width()

            self._table.setColumnWidth(i, max(header_width, sample_width))


    def _ui_ctx_menu_handler(self, position):
        """
        Handle right click context menu event on the coverage table.
        """

        # create a right click menu based on the state and context
        ctx_menu = self._populate_ctx_menu()
        if not ctx_menu:
            return

        # show the popup menu to the user, and wait for their selection
        action = ctx_menu.exec_(self._table.viewport().mapToGlobal(position))

        # process the user action
        self._process_ctx_menu_action(action)

    def _populate_ctx_menu(self):
        """
        Populate a context menu for the table view based on selection.
        Returns a populated QMenu, or None.
        """

        # get the list rows currently selected in the coverage table
        selected_rows = self._table.selectionModel().selectedRows()
        if len(selected_rows) == 0:
            return None

        # the context menu we will dynamically populate
        ctx_menu = QtWidgets.QMenu()

    
        ctx_menu.addAction(self._action_generate_stub)
        ctx_menu.addSeparator()
        ctx_menu.addAction(self._action_export_json)
        ctx_menu.addAction(self._action_decompile)

        # return the completed context menu
        return ctx_menu

    def _process_ctx_menu_action(self, action):
        """
        Process the given (user selected) context menu action.
        """

        # a right click menu action was not clicked. nothing else to do
        if not action:
            return

        # get the list rows currently selected in the coverage table
        selected_rows = self._table.selectionModel().selectedRows()
        if len(selected_rows) == 0:
            return

        for row in selected_rows:
            row_n = row.row()
            result = self._model._results[row_n]
            
            file_basename, file_ext = os.path.splitext(idaapi.get_root_filename())
            directory = os.path.dirname(idaapi.get_input_file_path())

            if action == self._action_generate_stub:

                file_basename = idc.AskStr("%s_%s" % (file_basename, result.IID), '[1/2] Enter stub name:')
                if not file_basename:
                    return

                directory = idc.AskStr(directory, '[2/2] Enter export directory:')
                if not directory:
                    return

                success = result.gen_c_struct(
                    directory,
                    file_basename,
                    self.rpc_results_db
                )


            elif action == self._action_export_json:
                json_export = result.json_export_result()
                
                default_filepath = os.path.join(
                    directory,
                    "%s_%s.json" % (file_basename, result.IID)
                )
                filepath = idc.AskStr(default_filepath, '[1/2] Enter json filepath:')
                if not filepath:
                    return

                with open(filepath, "w") as out:
                    out.write(json_export)

            elif action == self._action_decompile:

                if not os.environ.get("_NT_SYMBOL_PATH", None):
                    symbol_store = idc.AskStr("", '_NT_SYMBOL_PATH is not set, please enter the folder to the local symbol store :')
                    os.environ["_NT_SYMBOL_PATH"] = symbol_store

                result.decompile()

                
class RpcIdlForm( idaapi.PluginForm):

    html_template = """
<html>
<head>
<style>{style:s}</style>
</head>
<body>
<div style="white-space:pre">
{rows:s}
</div>
</body>
</html>
"""
    
    def OnCreate(self, form):
        
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

        self.browser = None
        self.layout = None
        return 1

    def PopulateForm(self):

        self.layout = QtWidgets.QVBoxLayout()
        self.browser = QtWidgets.QTextBrowser()
        self.browser.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.browser.setHtml(self.text)
        self.browser.setReadOnly(True)
        self.browser.setFontWeight(12)
        self.layout.addWidget(self.browser)
        self.parent.setLayout(self.layout)

    def Show(self, text, title):
        self.text = RpcIdlForm.html_template.format(rows = text, style="")
        return idaapi.PluginForm.Show(self, title)

#################################
## Results classes

RPC_HEADER_PLACEHOLDER = """
/* this ALWAYS GENERATED file contains the definitions for the interfaces */


/* File created by findrpc.py */


#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __{name:s}_h__
#define __{name:s}_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifdef __cplusplus
extern "C"{{
#endif 


#ifndef __{name:s}_INTERFACE_DEFINED__
#define __{name:s}_INTERFACE_DEFINED__

/* interface {name:s} */
/* FindRpc does not decode NDR streams, so you need to be figure out the prototype */ 

{procedures:s}


extern RPC_IF_HANDLE {name:s}_v1_0_c_ifspec;
extern RPC_IF_HANDLE {name:s}_v1_0_s_ifspec;
#endif /* __{name:s}_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}}
#endif

#endif
"""

class DetectedRpcStruct(namedtuple('DetectedRpcStruct','type address object IID')):
    """
    DetectedRpcStruct : detected rpc structure.
        - type : TYPE_XXXXX used to "apply type" on detected result
        - address : address of the structure
        - object : ctypes structure read
        - IID : InterfaceId of the detected FindRpcResult.
    """
    __slots__ = ()

    def __str__(self):
        return str(self.object)

class FindRpcResult(object):
    """
    FindRpcResult : detected rpc server interface.
    """

    def __init__ (self, IID, interface, interpreter):
        
        # IID : rpc server InterfaceId 
        self.IID = IID

        # interface : DetectedRpcStruct(RPC_SERVER_INTERFACE)
        self.interface = interface
        
        # interpreter : DetectedRpcStruct(MIDL_SERVER_INFO/MIDL_STUBLESS_PROXY_INFO)
        self.interpreter = interpreter

        # stub_desc : DetectedRpcStruct(MIDL_STUB_DESC)
        self.stub_desc = None

        # dispatch_table : DetectedRpcStruct(RPC_DISPATCH_TABLE)
        self.dispatch_table = None

        # syntax_info : list(DetectedRpcStruct(MIDL_SYNTAX_INFO))
        self.syntax_info = []

        # transfer_syntax : list(DetectedRpcStruct(RPC_SYNTAX_IDENTIFIER))
        self.transfer_syntax = None

        # try to detect if the rpc stub found is client side or server side
        self._is_client = None

    def get_syntax_guid(self):
        """
        Return the string representing detected RPC server InterfaceId.
        """
        
        if not self.interface:
            return None
        
        if not self.interface.object:
            return None

        return self.interface.object.InterfaceId.SyntaxGUID

    def is_client(self):
        """ Return if the extracted rpc info is a client stub or a server stub """
        if self._is_client is None:
           self._is_client = (self.get_proc_handlers() == None)  #|| (self.interpreter.type == TYPE_MIDL_SERVER_INFO)  

        return self._is_client

    def get_proc_handlers_table_ea(self):
        """ 
        If the detected rpc server has a dispatch table, get_proc_handlers_ea
        returns the address where the proc handlers table is located
        """

        if not self.interface.object.DispatchTable or not self.dispatch_table:
            return None

        if not self.dispatch_table.object.DispatchTableCount:
            return None

        if self.interpreter.type == TYPE_MIDL_SERVER_INFO:
            proc_handlers_address = self.interpreter.object.DispatchTable

        elif self.interpreter.type == TYPE_MIDL_STUBLESS_PROXY_INFO:
            proc_handlers_address = self.interpreter.object.ProcString

        else:
            return None

        

        return proc_handlers_address

    def get_proc_handlers_ea(self):
        """ 
        If the detected rpc server has a dispatch table, get_proc_handlers_ea
        returns the addresses of the array storing the procedure handlers.
        """

        proc_handlers_address = self.get_proc_handlers_table_ea()

        if not proc_handlers_address:
            return None
        
        # since get_proc_handlers_table_ea succeed, it means DispatchTableCount > 0
        proc_handlers_count = self.dispatch_table.object.DispatchTableCount
        proc_handlers = [[]]*proc_handlers_count

        return [ proc_handlers_address + ph_ea*POINTER_SIZE for ph_ea in range(0, proc_handlers_count)]

    def get_proc_handlers(self):
        """ 
        If the detected rpc server has a dispatch table, get_proc_handlers_ea
        returns the addresses of all procedure handlers.
        """

        ph_eas = self.get_proc_handlers_ea()
        if not ph_eas:
            return None

        return [ READ_PTR_VALUE(ph_ea) for ph_ea in ph_eas]

    def get_proc_names(self):

        for ea in self.get_proc_handlers():
            func_name = idaapi.get_name(ea)   
            if not func_name:
                func_name = "fun_%08x" % ea

            yield func_name


    def _print_address(self, member):
        """
        Pretty print the address of a member, if present.
        """

        if not hasattr(self, member):
            return "None"

        result = getattr(self, member)
        if not result:
            return "None"

        if type(result) is list:
            return "[%s]" % ",".join("0x%x" % o.address for o in  result)

        return "0x%x" % result.address

    def _print_proc_handlers(self):
        """
        Pretty print the address of all procedure handlers, if present.
        """

        proc_handlers = self.get_proc_handlers()
        if not proc_handlers:
            return None

        str_proc_handlers = [ "-0x%x" % ea for ea in proc_handlers ]
        str_proc_handlers.insert(0, "-proc_handlers :")
        return "\n\t".join(str_proc_handlers)


    def __str__(self):
        elements = [
            "-stub_type: %s" % ("server", "client")[self.is_client()],
            "-IID: %s" % self.get_syntax_guid(),
            "-interface: %s" % self._print_address('interface'),
            "-interpreter: %s" % self._print_address('interpreter'),
            "-stub_desc: %s" % self._print_address('stub_desc'),
            "-dispatch_table: %s" % self._print_address('dispatch_table'),
            "-syntax_info: %s" % self._print_address('syntax_info'),
            "-transfer_syntax: %s" % self._print_address('transfer_syntax'),
        ]

        proc_handlers_str = self._print_proc_handlers()
        if proc_handlers_str:
            elements.append(proc_handlers_str)

        return "\n".join(elements)

    def generate_header(self, header_filepath, struct_prefix):

        logging.info("writing header file for %s in : %s" % (struct_prefix, header_filepath))

        # generate placeholding procedures
        # TODO : improve namimg based on whether it's a client or a server
        if self.is_client():
            # in stubless clients, the MIDL_DESC is used in every call
            # TODO : this is bad since we can have duplicates
            xrefs = list(filter(lambda x: not is_address_in_data_section(x.frm), XrefsTo(self.stub_desc.address)))
            num_procedures = len(xrefs) 
            
            procedures = "\n\n".join(map(lambda n: "void Proc%d();" % n, range(num_procedures)))
        else:
            procedures = "\n\n".join(map(lambda f: "void %s();" % f, self.get_proc_names()))

        with open(header_filepath, "w") as header:
            
            #----------------------------------------------------------------------
            # header guard and includes
            #----------------------------------------------------------------------
            header.write(RPC_HEADER_PLACEHOLDER.format(
                name = struct_prefix,
                procedures = procedures
            ))



    def gen_c_struct(self, folder, filename, fa, bytes_read = 0x100):

        struct_prefix = filename.replace("(", "").replace(")", "").replace("-", "_").replace(".", "_")
    
        header_filepath = os.path.join(folder, "%s.h" % filename)
        source_filepath = os.path.join(folder, "%s_%s.c" % (filename, ("s", "c")[self.is_client()]))

        self.generate_header(header_filepath, struct_prefix)

        with open(source_filepath, "w") as header:

            # header guard and includes
            
            # Forward references
            header.write("// Forward references\n")
            if self.dispatch_table:
                header.write("extern const RPC_DISPATCH_TABLE %s;\n" % RPC_DISPATCH_TABLE.get_c_instance_name(struct_prefix))

            if self.interpreter:
                header.write("extern const %s %s;\n" % (
                    ("MIDL_SERVER_INFO", "MIDL_STUBLESS_PROXY_INFO")[self.interpreter.type == MIDL_STUBLESS_PROXY_INFO],
                    self.interpreter.object.__class__.get_c_instance_name(struct_prefix)
                ))

            if self.stub_desc:
                header.write("extern const MIDL_STUB_DESC %s;\n" % (
                    self.stub_desc.object.__class__.get_c_instance_name(struct_prefix)
                ))

            header.write("// end Forward references\n")
            header.write("\n\n")
            
            # Structures
            if self.dispatch_table:
                header.write(self.dispatch_table.object.gen_c_struct(struct_prefix, fa))
                header.write("\n\n")

            header.write(self.stub_desc.object.gen_c_struct(struct_prefix, fa))
            if self.interpreter:
                header.write(self.interpreter.object.gen_c_struct(struct_prefix, fa, bytes_read =  bytes_read))
            header.write(self.interface.object.gen_c_struct(struct_prefix, fa, is_client = self.is_client()))

    def json_export_result(self, bytes_read = 0x1000):
        """
        Export detected result as a json formated string.
        note: FmtStringOffset, ProcString and FormatTypes does not have a "length" (we have to parse Ndr syntax in order to know it) 
                so tweak `bytes_read` parameter to export the entirety.
        """

        def get_optional_object(detected_struct):
            if not detected_struct:
                return None
            return  detected_struct.object

        def get_optional_address(detected_struct):
            if not detected_struct:
                return 0
            return detected_struct.address


        exportable_data = {

            # "raw" RPC structures
            "ServerInterface": self.interface.object,
            "StubDesc": self.stub_desc.object,
            "DispatchTable": get_optional_object(self.dispatch_table),
            "InterpretorInfo": get_optional_object(self.interpreter),
            "TransferSyntax": get_optional_object(self.transfer_syntax),
            "SyntaxInfo": [ si.object for si in self.syntax_info],

            #  
            "ProcHandlers" : self.  get_proc_handlers(),

            # Unsized arrays => we store only the file offset
            "FmtStringOffset" : idaapi.get_fileregion_offset(self.interpreter.object.FmtStringOffset),
            "ProcString" : idaapi.get_fileregion_offset(self.interpreter.object.ProcString), 
            "FormatTypes" : idaapi.get_fileregion_offset(self.stub_desc.object.pFormatTypes), 

            # instances structures address for linking structures
            "ImageBaseAddress" : idaapi.get_imagebase(),
            "ServerInterfaceAddress":  self.interface.address,
            "StubDescAddress": self.stub_desc.address,
            "DispatchTableAddress": getattr(self.dispatch_table, "address", 0x00),
            "InterpretorInfoAddress": get_optional_address(self.interpreter),
            "TransferSyntaxAddress": get_optional_address(self.transfer_syntax),
            "SyntaxInfoAddress": [ si.address for si in self.syntax_info],
            "ProcHandlersAddress" : self.get_proc_handlers_ea(),
            "FmtStringOffsetAddress" : self.interpreter.object.FmtStringOffset,
            "ProcStringAddress" : self.interpreter.object.ProcString,
            "FormatTypesAddress" : self.stub_desc.object.pFormatTypes,

            # Useful metadatas
            "DllName" : idaapi.get_root_filename(),
            "Filepath" : idaapi.get_input_file_path(),
        }

        return json.dumps(exportable_data, cls=CDataJSONEncoder)

    def decompile(self):
        import subprocess
        import tempfile

        tmp_json = "%s.json" % tempfile.mktemp()
        with open(tmp_json, "w") as out:
            out.write(self.json_export_result())

        decompiler_path = os.path.join (
            os.path.dirname(get_script_filepath()),
            "decompile",
            "DecompileInterface.exe"
        )

        # Run the decompiler without showing the console
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            output = subprocess.check_output([
                decompiler_path,
                tmp_json
            ], startupinfo=si)
        except subprocess.CalledProcessError as cpe:
            idaapi.warning("Could not decompile RPC interface %s" % (self.get_syntax_guid()))
            return

     
        # Clean up output and formating
        output = output.replace("/* Stack Offset:", "\r\n\t\t/* Stack Offset:")
        output = output.replace("\t", "&emsp;")

        rows = output.split("\r\n")
        html_rows = "\n".join(map(lambda r:"<p>%s</p>" % r, rows))
        form_title = "Decompiled IDL for interface %s" % self.get_syntax_guid()

        # Launch a custom form to display the idl
        idl_result = RpcIdlForm()
        idl_result.Show(html_rows, form_title)
        

#################################
## search functions

def is_address_in_data_section(ea):
    """
    Check the given addres is not part of an executable section (i.e. "data" section).
    """

    if not ida_bytes.is_loaded(ea):
        return False

    seg = idaapi.getseg(ea)
    read_access = (seg.perm & idaapi.SEGPERM_READ) >> 2
    exec_access = (seg.perm & idaapi.SEGPERM_EXEC)

    if exec_access:
        return False

    if not read_access:
        return False
    
    return True

def get_data_sections():
    """
    Return all non-executable data section in the binary
    """

    for n in xrange(get_segm_qty()):
        seg = getnseg(n)

        if not seg: 
            continue

        # For some linux binaries
        # Ida does not recognize the segment
        # permissions (usually for plt)
        if seg.perm == 0:
            continue

        read_access = (seg.perm & idaapi.SEGPERM_READ) >> 2
        exec_access = (seg.perm & idaapi.SEGPERM_EXEC)

        # filter out X sections
        # TODO : check if it's a correct assumption
        if exec_access:
            continue

        if not read_access:
            continue

        yield seg


def read_ctypes_structure(address, ctypes_structure):
    """
    Unpack raw data as a ctype structure.
    """

    if not address:
        return None

    # TODO : This test is flaky, find a way to correctly test if an address if valid
    # before dereferencing
    if not ida_bytes.is_loaded(address):
        return None

    ctypes_object = ctypes_structure()
    structure_size = ctypes.sizeof(ctypes_object)

    raw_buffer = idaapi.get_many_bytes(address, structure_size)
    ctypes.memmove(ctypes.addressof(ctypes_object), raw_buffer, structure_size)

    return ctypes_object

def read_rpc_interpreter_info(interface_obj, address):
    """
    Read the InterpreterInfo pointer, either as a MIDL_SERVER_INFO or MIDL_STUBLESS_PROXY_INFO structure.
    """

    # Servers usually has interpreter info
    if interface_obj.has_interpreter_info():
        interpreter_obj = read_ctypes_structure (address, MIDL_SERVER_INFO)
        interpreter_type = TYPE_MIDL_SERVER_INFO
        interpreter_ctype = MIDL_SERVER_INFO
        return interpreter_ctype, interpreter_type, interpreter_obj

    # clients can have proxy info
    if interface_obj.has_proxy_info():
        interpreter_obj = read_ctypes_structure (address, MIDL_STUBLESS_PROXY_INFO)
        interpreter_type = TYPE_MIDL_STUBLESS_PROXY_INFO
        interpreter_ctype = MIDL_STUBLESS_PROXY_INFO
        return interpreter_ctype, interpreter_type, interpreter_obj


    # What are you trying to read ?
    return (None, None, None)

def get_structure_name_at_address(address):
    """ 
    Return the name of the structure currently applied if it exists, 
    otherwise None.
    """
    
    ti = idaapi.opinfo_t()
    flags = idc.GetFlags(address)
    
    if not idaapi.get_opinfo(address, 0, flags, ti):
        return None
    
    return idaapi.get_struc_name(ti.tid)


class FindRpc(object):
    """
        FindRpc : helper class which scan the opened binary in order to find characteristic RPC structures.
    """

    def __init__(self):

        # _process_queue_list : rpc structures propagation queue
        self._process_queue_list = [] 

        # _processed_items : rpc structures propagated items (in order to break circular references)
        self._processed_items = {}

        # results : list of FindRpcResults items
        self.results = []

    def query_rpc_struct(self, address):
        
        if not address:
            return None

        if not self._processed_items.get(address, None):
            raise ValueError("no rpc struct found at address 0x%x" % address)

        return self._processed_items[address].object


    def binwalk_rpc_server_interface_structures(self):
        """
        From detected markers, attempt to reconstruct RPC structures (RPC_SERVER_INTERFACE, MIDL_SERVER_INFO, etc.).
        note: tweak the heuristics in this method to improve detection.
        """

        # initial search
        for (ea, xrefs, data_xrefs) in self._bingrep_rpc_server_interface_marker():

            # read data as RPC_SERVER_INTERFACE
            interface_obj = read_ctypes_structure (ea, RPC_SERVER_INTERFACE)
            if not interface_obj:
                continue

            # interface_obj.InterpreterInfo is optional for stubless clients, but if set it must point to a correct address in a R(W) section
            if interface_obj.InterpreterInfo and (not is_address_in_data_section(interface_obj.InterpreterInfo)):
                continue

            # interface_obj.DispatchTable is optional, but if set it must point to a correct address in a R(W) section
            if interface_obj.DispatchTable and (not is_address_in_data_section(interface_obj.DispatchTable)):
                continue


            guid = interface_obj.InterfaceId.SyntaxGUID
            result = FindRpcResult(guid, None, None)
            logging.debug ("[findrpc] [!] Found rpc server/client interface : %x - %s" % (ea, guid))

            result.interface = self._decode_rpc_structure(
                ea,
                RPC_SERVER_INTERFACE,
                TYPE_RPC_SERVER_INTERFACE,
                result,
                optional = False
            )

            # TODO : are all RPC_SERVER_INTERFACE instances must have a interface_obj.InterpreterInfo ?
            # MISC : some stubless clients does not have interpreter informations. In that case, use xrefs to locate the
            #        MIDL_STUB_DESC information and go the otherway around using hex(list(XrefsTo(here()))[0].frm)
            if interface_obj.InterpreterInfo:
                
                # Read  InterpreterInfo structure
                interpreter_ctype , interpreter_type, interpreter_obj = read_rpc_interpreter_info(interface_obj, interface_obj.InterpreterInfo)
                if interpreter_obj:

                    result.interpreter = self._decode_rpc_structure(
                        interface_obj.InterpreterInfo,
                        interpreter_ctype,
                        interpreter_type,
                        result,
                        optional = True
                    )

                    logging.debug ("[findrpc]   - interpreter info : %x" % (interface_obj.InterpreterInfo))
                    logging.debug ("[findrpc]   - stub descriptor : %x" % (interpreter_obj.pStubDesc))

            yield result

    def search_rpc_structures(self):
        """
        Search and return rpc structures within the binary.
        """

        # initial binary grep search and heuristics
        for initial_result in self.binwalk_rpc_server_interface_structures():

            self.results.append(initial_result)

            # structures propagation
            for result in self._propagate_rpc_results():

                logging.debug("[findrpc] [!] Found %s struct at 0%x" % (result.type, result.address))
                yield result

                if result.type == TYPE_MIDL_STUB_DESC:
                    initial_result.stub_desc = result
                elif result.type == TYPE_RPC_DISPATCH_TABLE:
                    initial_result.dispatch_table = result
                elif result.type == TYPE_MIDL_SYNTAX_INFO:
                    initial_result.syntax_info.append(result)
                elif result.type == TYPE_RPC_SYNTAX_IDENTIFIER:
                    initial_result.transfer_syntax = result
                    

            # debug print
            print("[findrpc] (+) rpc informations for IID : %s" % initial_result.IID)
            print("%s" % str(initial_result))

    def c_export_result(self, result, folder, filename, bytes_read = 0x100):
        """
        Export detected result as a C stub.
        note: FmtStringOffset, ProcString and FormatTypes does not have a "length" (we have to parse Ndr syntax in order to know it) 
                so tweak `bytes_read` parameter to export the entirety.
        """
        result.gen_c_struct(folder, filename, self, bytes_read=bytes_read)



    def _decode_rpc_structure(self, address, ctypes_type, findrpc_type, IID, optional = True):
        """
        Parse data located at a given address as a particular ctypes structure, if possible.
        """

        # do not process twice the same item
        if address in self._processed_items:
            return self._processed_items[address]

        ctypes_object = read_ctypes_structure (address, ctypes_type)

        # some rpc fields are optional, in that case do not propagate results
        if optional and not ctypes_object:
            return None

        item = DetectedRpcStruct(
            type = findrpc_type,
            address = address,
            object = ctypes_object,
            IID = IID
        )

        # new item decoded : add it to the process list
        self._process_queue_list.append(item)
        self._processed_items[address] = item

        return item

    def _propagate_rpc_results(self):
        """
        "Taint" propagation of detected rpc structures results.
        """

        # recursive "taint" propagation
        while len(self._process_queue_list) > 0:

            # LIFO style
            item = self._process_queue_list.pop(0)
            xrefs = list(filter(lambda x: is_address_in_data_section(x.frm), XrefsTo(item.address)))

            if item.type == TYPE_RPC_SERVER_INTERFACE:
                
                # Dispatch table is optional
                self._decode_rpc_structure(
                    item.object.DispatchTable,
                    RPC_DISPATCH_TABLE,
                    TYPE_RPC_DISPATCH_TABLE,
                    item.IID,
                )

                # potential TYPE_MIDL_STUB_DESC structure referencing the interface
                if len(xrefs) == 1:
                    midl_stub_desc_ea = xrefs[0].frm
                    
                    self._decode_rpc_structure(
                        midl_stub_desc_ea,
                        MIDL_STUB_DESC,
                        TYPE_MIDL_STUB_DESC,
                        item.IID,
                    )


            elif item.type == TYPE_MIDL_SERVER_INFO or item.type == TYPE_MIDL_STUBLESS_PROXY_INFO:

                self._decode_rpc_structure(
                    item.object.pStubDesc,
                    MIDL_STUB_DESC,
                    TYPE_MIDL_STUB_DESC,
                    item.IID,
                )

                self._decode_rpc_structure(
                    item.object.pTransferSyntax,
                    RPC_SYNTAX_IDENTIFIER,
                    TYPE_RPC_SYNTAX_IDENTIFIER,
                    item.IID,
                )

                
                for i in range(0, max(item.object.nCount, 2)):
                    
                    self._decode_rpc_structure(
                        item.object.pSyntaxInfo + i*ctypes.sizeof(MIDL_SYNTAX_INFO),
                        MIDL_SYNTAX_INFO,
                        TYPE_MIDL_SYNTAX_INFO,
                        item.IID,
                    )         



            # TODO 
            elif item.type == TYPE_MIDL_SYNTAX_INFO:
                pass

            elif item.type == TYPE_MIDL_STUB_DESC:

                # potential MIDL_SERVER_INFO/MIDL_STUBLESS_PROXY_INFO structure referencing the interface
                if len(xrefs) == 1:
                    midl_info_ea = xrefs[0].frm

                    interface = self._decode_rpc_structure(
                        item.object.RpcInterfaceInformation,
                        RPC_SERVER_INTERFACE,
                        TYPE_RPC_SERVER_INTERFACE,
                        item.IID,
                    )

                    if interface:

                        # Read  InterpreterInfo structure
                        interpreter_ctype , interpreter_type, interpreter_obj = read_rpc_interpreter_info(interface.object, midl_info_ea)
                        
                        self._decode_rpc_structure(
                            midl_info_ea,
                            MIDL_STUB_DESC,
                            TYPE_MIDL_STUB_DESC,
                            item.IID,
                        )

            yield item

    def _bingrep_rpc_server_interface_marker(self):
        """
        Binary search the RPC_SERVER_INTERFACE.Length marker in R(W) data sections, a la "binwalk"
        """
        rpc_server_interface_marker = "%02X" % ctypes.sizeof(RPC_SERVER_INTERFACE)

        for seg in get_data_sections():
            logging.debug ("[findrpc] scanning [%x - %x] %s" % (seg.startEA, seg.endEA, idaapi.get_segm_name(seg)))

            ea = seg.startEA
            nea = ea
            while True:

                ea = FindBinary(nea, SEARCH_DOWN, rpc_server_interface_marker)
                if (ea == idaapi.BADADDR) or (ea > seg.endEA):
                    break

                nea = ea + POINTER_SIZE

                # Check the whole dword is equal to the marker, not just a byte
                if ctypes.sizeof(RPC_SERVER_INTERFACE) != ida_bytes.get_dword(ea):
                    continue
                
                # if there is already a structure applied, and it's not a RPC_SERVER_INTERFACE, keep on going
                correct_types = ["RPC_SERVER_INTERFACE", "_RPC_SERVER_INTERFACE", "RPC_CLIENT_INTERFACE", "_RPC_CLIENT_INTERFACE"]
                applied_type = get_structure_name_at_address(ea)
                if applied_type and applied_type not in correct_types:
                    continue

                # RPC_SERVER_INTERFACE usually does have some X-refs towards them, 
                # especially xrefs from data sections
                xrefs = list(DataRefsTo(ea)) 
                if not len(xrefs):
                    continue

                data_xrefs = []
                for xref in xrefs:
                    if is_address_in_data_section(xref):
                        data_xrefs.append(xref)

                if not len(data_xrefs):
                    continue

                logging.debug ("[findrpc] [!] Found rpc server marker : %x" % (ea))
                yield (ea, xrefs, data_xrefs)


#################################
## script

def preload_standard_rpc_structures():
    """
    Preload windows types that will be applied on detected structures.
    """

    Til2Idb(-1, TYPE_RPC_SERVER_INTERFACE)
    Til2Idb(-1, TYPE_MIDL_STUB_DESC)
    Til2Idb(-1, TYPE_MIDL_SYNTAX_INFO)
    Til2Idb(-1, TYPE_MIDL_SERVER_INFO)
    Til2Idb(-1, TYPE_MIDL_STUBLESS_PROXY_INFO)
    Til2Idb(-1, TYPE_RPC_SYNTAX_IDENTIFIER)
    Til2Idb(-1, TYPE_RPC_DISPATCH_TABLE)


def check_isa_is_intel():
    return idaapi.ph_get_id() == idaapi.PLFM_386

def check_binary_is_pe():
    # Seriously, this is how someone test if the currently loaded binary is a PE file ?
    # How about making a enum, and a `idainfo.get_filetype()` function ?
    return idc.get_inf_attr(idc.INF_FILETYPE) == idc.FT_PE

def get_script_filepath():
    # Since IDA rely on exec'd scripts, __file__ is unusable
    return os.path.abspath(inspect.getframeinfo(inspect.currentframe()).filename)

def main():
    preload_standard_rpc_structures()

    # Don't bother searching for RPC features in non-x86 non-PE files
    if not check_isa_is_intel() or not check_binary_is_pe():
        return


    print("=======================================")
    print("[findrpc] RPC structures search :")
    fr = FindRpc()
    detected_rpc_structs = list(fr.search_rpc_structures())
    print("=======================================")

        
    # Show results
    rpc_detected_struct_form = RpcResultsForm(detected_rpc_structs)
    rpc_results_form = FindRpcResultsForm(fr)

    rpc_detected_struct_form.show()
    rpc_results_form.show()





if __name__ == '__main__':
    import ida_auto

    if not ida_auto.auto_is_ok():
        warning("Wait for autoanalysis to finish before launching findrpc")
    else:
        main()
