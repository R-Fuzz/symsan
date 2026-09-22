from ctypes import * # type: ignore
from re import match, sub
from types import new_class

strip = lambda s: sub(r'\s+', ' ', s)
class_name = lambda s: sub(r"(_|-)+", " ", s).title().replace(" ", "")

class StructParser:
    def __init__(self, filename: str, base: object = object) -> None:
        ctype_mapping = {
            "int": c_int,
            "float": c_float,
            "double": c_double,
            "char": c_char,
            "void*": c_void_p,
            "unsigned int": c_uint32,
            "unsigned long long": c_uint64,
            "unsigned char": c_uint8,
            "unsigned short": c_uint16,
            "long long": c_int64
        }
        self.data = open(filename).read()
        self.types = {}
        state = []
        fields = []
        buf = ""
        for line in self.data.splitlines():
            buf += line.split("//")[0] + ' '
            m = match(r"\s*typedef\s+(.*)\s+([^\s]+)\s*;", line)
            if m:
                if m[1].endswith('*'):
                        ctype_mapping[strip(m[2])] = ctype_mapping['void*']
                else:
                    ctype_mapping[strip(m[2])] = ctype_mapping[strip(m[1])]
                buf = buf.replace(m[0], "", 1)
                continue
            m = match(r"\s*struct\s+([^\s]+)\s*\{", line)
            if m:
                state.append([class_name(m[1]), fields])
                fields = []
                buf = buf.replace(m[0], "", 1)
                continue
            m = match(r"\s*\}\s*(.*)\s*;", line)
            if m:
                sn, parent_fields = state.pop() # struct name
                attr_raw = m[1]
                attrs = {}
                if "packed" in attr_raw: # attribute not cover all cases yet
                    m_align = match(r"aligned\s*\(\s*(\d+)\s*\).*", attr_raw)
                    if m_align:
                        attrs["_pack_"] = int(m_align[1])
                    else:
                        attrs["_pack_"] = 1
                attrs["_fields_"] = fields
                # print(sn, attrs)
                struct_cls = new_class('_' + sn, (Structure,), {}, lambda ns: ns.update(attrs))
                # cls = new_class(sn, (Structure,), attrs)
                parent_fields.append((sn, struct_cls))
                fields = parent_fields
                buf = buf.replace(m[0], "", 1)
                continue
            m = match(r"\s*([\w\s]+)\s+([^\s]+)\s*;", line)
            if m:
                sub_test = match(r'(.*):(\d+)$', m[2])
                if sub_test:
                    fields.append((sub_test[1], ctype_mapping[strip(m[1])], int(sub_test[2])))
                else:
                    sub_test = match(r'(.*)\[(\d+)\]$', m[2])
                    if sub_test:
                        fields.append((sub_test[1], ctype_mapping[strip(m[1])] * int(sub_test[2])))
                    else:
                        fields.append((m[2], ctype_mapping[strip(m[1])]))
                buf = buf.replace(m[0], "", 1)
                continue
        for k, v in fields:
            cls = new_class(k, (base,), {}, lambda ns: ns.update({"Struct": v, "size": sizeof(v)}))
            self.types[k] = cls