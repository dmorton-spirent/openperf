import argparse
import os
import pathlib
import sys
import textwrap
import yaml


HEADER_GUARD="_OP_PACKET_PROTOCOL_TRANSMOGRIFY_{}_HPP_"
TRANSMOGRIFY_NAMESPACE="openperf::packet::protocol::transmogrify"
LIBPACKET_NAMESPACE="libpacket"
SWAGGER_NAMESPACE="swagger::v1::model"

LIBPACKET_PATH="packet/protocol"
SWAGGER_PATH="swagger/v1/model"


def write_file_header(output, name, kind):
    header='''
    /**
     * swagger <-> libpacket transmogrify {kind} for {name}
     *
     * This file is automatically generated by the transmogrify code generator.
     * Do not edit this file manually.
     **/
    '''

    output.write(textwrap.dedent(header.format(name=name,kind=kind)).lstrip())

def write_cr(output):
    output.write('\n')


class cpp_indenter():
    def __init__(self, output):
        self.output = output

    def write(self, s):
        self.output.write('    ' + s)


class cpp_header_guard():
    def __init__(self, output, name):
        self.guard = HEADER_GUARD.format(name.upper())
        self.output = output

    def __enter__(self):
        self.output.write('#ifndef {}\n'.format(self.guard))
        self.output.write('#define {}\n'.format(self.guard))
        write_cr(self.output)
        return cpp_indenter(self.output)

    def __exit__(self, type, value, traceback):
        write_cr(self.output)
        self.output.write('#endif /* {} */\n'.format(self.guard))


class cpp_namespace():
    def __init__(self, output):
        self.output = output

    def __enter__(self):
        self.output.write('namespace {} {{\n'.format(TRANSMOGRIFY_NAMESPACE))
        write_cr(self.output)
        return cpp_indenter(self.output)

    def __exit__(self, type, value, traceback):
        write_cr(self.output)
        self.output.write('}\n')


class cpp_scope():
    def __init__(self, output, text = None):
        self.output = output
        self.text = text

    def __enter__(self):
        if self.text:
            if self.text[-1] != '{':
                line = (self.text + '\n{\n')
            else:
                line = (self.text + '\n')
            self.output.write(line)
        else:
            self.output.write('{\n')

        return cpp_indenter(self.output)

    def __exit__(self, type, value, traceback):
        self.output.write('}\n')


def to_file_basename(name):
    return name.lower()


def to_libpacket_header(name):
    return os.path.join(LIBPACKET_PATH, '{}.hpp'.format(name.lower()))


def to_libpacket_object(name):
    return '{}::protocol::{}'.format(LIBPACKET_NAMESPACE, name.lower())


def to_swagger_header(name):
    return os.path.join(SWAGGER_PATH, 'PacketProtocol{}.h'.format(name.lower().capitalize()))


def to_swagger_cpp_object(name):
    return '{}::PacketProtocol{}'.format(SWAGGER_NAMESPACE, name.lower().capitalize())


def to_swagger_object(name):
    return 'std::shared_ptr<{}>'.format(to_swagger_cpp_object(name))


def to_swagger_declaration(name, arg = None):
    return '{} to_swagger(const {}&{})'.format(to_swagger_object(name),
                                               to_libpacket_object(name),
                                               ' {}'.format(arg) if arg else '')


def to_libpacket_declaration(name, arg = None):
    return '{} to_protocol(const {}&{})'.format(to_libpacket_object(name),
                                                to_swagger_object(name),
                                                ' {}'.format(arg) if arg else '')


def write_transmogrify_header(output, name, data):
    with cpp_header_guard(output, to_file_basename(name)):

        write_file_header(output, name, "header")
        write_cr(output)

        output.write('#include "{}"\n'.format(to_libpacket_header(name)))
        output.write('#include "{}"\n'.format(to_swagger_header(name)))
        write_cr(output)

        with cpp_namespace(output):
            output.write('{};\n'.format(to_libpacket_declaration(name)))
            write_cr(output)

            output.write('{};\n'.format(to_swagger_declaration(name)))


def is_swagger_bool(props):
    return 'length' in props and props['length'] == 1


def to_swagger_checker(field, props):
    tokens = field.split('_')

    # XXX: Flags need to have their vector checked for size because the
    # 'isSet' flag is never actually set in the swagger object!
    if ('format' in props and props['format'] == 'enumeration' and 'uniqueItems' not in props):
        return 'get' + ''.join(t.capitalize() for t in tokens) + '().size'
    else:
        return tokens[0] + ''.join(t.capitalize() for t in tokens[1:]) + 'IsSet'


def to_swagger_getter(field, props):
    prefix = 'is' if 'length' in props and props['length'] == 1 else 'get'
    tokens = field.split('_')
    return prefix + ''.join(t.capitalize() for t in tokens)


def to_swagger_setter(field):
    tokens = field.split('_')
    return 'set' + ''.join(t.capitalize() for t in tokens)


def to_libpacket_getter(name, field):
    return 'get_{}_{}'.format(name.lower(), field)


def to_libpacket_setter(name, field):
    return 'set_{}_{}'.format(name.lower(), field)


def to_libpacket_enum_type(name, field):
    return '{}::protocol::{}::{}_value'.format(LIBPACKET_NAMESPACE, name.lower(), field)


def to_libpacket_enum(name, field, enum):
    return '{}::{}'.format(to_libpacket_enum_type(name, field), enum)


def to_libpacket_bit_flag_type(name, field):
    return '{}::type::bit_flags<{}>'.format(LIBPACKET_NAMESPACE, to_libpacket_enum_type(name, field))


def to_libpacket_field_conversion(name, field):
    return 'to_{}_{}'.format(name.lower(), field)


def write_set_swagger_value_default(output, src, dst, name, field, props):
    output.write('{dst}->{swagger_fn}({protocol_fn}({src}));\n'
                 .format(swagger_fn=to_swagger_setter(field),
                         protocol_fn=to_libpacket_getter(name, field),
                         dst=dst,
                         src=src))


def write_set_swagger_value_address(output, src, dst, name, field, props):
    output.write('{dst}->{swagger_fn}(to_string({protocol_fn}({src})));\n'
                 .format(swagger_fn=to_swagger_setter(field),
                         protocol_fn=to_libpacket_getter(name, field),
                         dst=dst,
                         src=src))


def write_set_swagger_value_enum(output, src, dst, name, field, props):
    output.write('switch(auto {field}_value = {protocol_fn}({src})) {{\n'
                 .format(field=field,
                         protocol_fn=to_libpacket_getter(name, field),
                         src=src))
    for item in props['items']:
        for enum in item.keys():
            output.write('case {}:\n'.format(to_libpacket_enum(name, field, enum)))
            output.write('    {dst}->{swagger_fn}("{string}");\n'
                         .format(dst=dst,
                                 swagger_fn=to_swagger_setter(field),
                                 string=enum))
            output.write('    break;\n')
    output.write('}\n')


def write_set_swagger_value_flags(output, src, dst, name, field, props):
    output.write('auto {src}_{field} = {protocol_getter}({src});\n'
                 .format(src=src,
                         field=field,
                         protocol_getter=to_libpacket_getter(name, field)))
    for item in props['items']:
        for enum in item.keys():
            output.write('if ({src}_{field} & {enum})\n'
                         .format(src=src, field=field, enum=to_libpacket_enum(name, field, enum)))
            output.write('{\n')
            output.write('    {dst}->{swagger_getter}().emplace_back("{string}");\n'
                         .format(dst=dst,
                                 swagger_getter=to_swagger_getter(field, props),
                                 string=enum))
            output.write('}\n')


def write_set_swagger_value_enumeration(output, src, dst, name, field, props):
    write_cr(output)
    if 'uniqueItems' in props:
        write_set_swagger_value_enum(output, src, dst, name, field, props)
    else:
        write_set_swagger_value_flags(output, src, dst, name, field, props)
    write_cr(output)


def write_to_swagger_impl(output, name, data):
    format_dispatch = {
        'ipv4': write_set_swagger_value_address,
        'ipv6': write_set_swagger_value_address,
        'mac': write_set_swagger_value_address,
        'enumeration': write_set_swagger_value_enumeration
    }

    arg = 'src'
    output.write('{}\n'.format(to_swagger_declaration(name, arg)))
    with cpp_scope(output)as f:
        f.write('auto dst = std::make_shared<{}>();\n'.format(to_swagger_cpp_object(name)))
        write_cr(output)

        for field, props in data.items():
            if 'format' in props and props['format'] in format_dispatch:
                writer = format_dispatch[props['format']]
            else:
                writer = write_set_swagger_value_default

            writer(f, arg, 'dst', name, field, props)

        write_cr(output)
        f.write('return (dst);\n')


def write_set_libpacket_value_default(output, src, dst, name, field, props):
    output.write('if ({src}->{swagger_fn}())\n'.format(src=src, swagger_fn=to_swagger_checker(field, props)))
    output.write('{\n')
    output.write('    {protocol_fn}({dst}, {src}->{swagger_fn}());\n'
                 .format(protocol_fn=to_libpacket_setter(name, field),
                         swagger_fn=to_swagger_getter(field, props),
                         dst=dst,
                         src=src))
    output.write('}\n')


def write_set_libpacket_value_address(output, src, dst, name, field, props):
    output.write('if ({src}->{swagger_fn}())\n'.format(src=src, swagger_fn=to_swagger_checker(field, props)))
    output.write('{\n')
    output.write('    {protocol_fn}({dst}, {ns}::type::{kind}_address({src}->{swagger_fn}()));\n'
                 .format(protocol_fn=to_libpacket_setter(name, field),
                         swagger_fn=to_swagger_getter(field, props),
                         ns=LIBPACKET_NAMESPACE,
                         kind=props['format'].lower(),
                         dst=dst,
                         src=src))
    output.write('}\n')


def write_set_libpacket_value_enumeration(output, src, dst, name, field, props):
    output.write('if ({src}->{swagger_fn}())\n'.format(src=src, swagger_fn=to_swagger_checker(field, props)))
    output.write('{\n')
    output.write('    {protocol_fn}({dst}, {conv_fn}({src}->{swagger_fn}()));\n'
                 .format(protocol_fn=to_libpacket_setter(name, field),
                         conv_fn=to_libpacket_field_conversion(name, field),
                         swagger_fn=to_swagger_getter(field, props),
                         kind=props['format'].lower(),
                         dst=dst,
                         src=src))
    output.write('}\n')


def write_set_libpacket_flag_conversion(output, name, field, props):
    output.write('static {} {}(std::vector<std::string>& values)\n'
                 .format(to_libpacket_bit_flag_type(name, field),
                         to_libpacket_field_conversion(name, field)))
    with cpp_scope(output) as scope:
        scope.write('auto tmp = {}{{0}};\n'
                     .format(to_libpacket_bit_flag_type(name, field)))
        scope.write('for (auto& value : values)\n')
        scope.write('{\n')
        for idx, item in enumerate(props['items']):
            for enum in item.keys():
                scope.write('    {} (value == "{}")\n'
                             .format('if' if idx == 0 else 'else if',
                                     enum))
                scope.write('    {\n')
                scope.write('        tmp |= {};\n'.format(to_libpacket_enum(name, field, enum)))
                scope.write('    }\n')
        scope.write('}\n')
        scope.write('return (tmp);\n')


def write_set_libpacket_enum_conversion(output, name, field, props):
    output.write('static enum {} {}(std::string_view value)\n'
                 .format(to_libpacket_enum_type(name, field),
                         to_libpacket_field_conversion(name, field)))
    with cpp_scope(output) as e:
        for idx, item in enumerate(props['items']):
            for enum in item.keys():
                e.write('{} (value == "{}")\n'
                             .format('if' if idx == 0 else 'else if',
                                     enum))
                e.write('{\n')
                e.write('    return ({});\n'
                             .format(to_libpacket_enum(name, field, enum)))
                e.write('}\n')

        write_cr(output)
        output.write('    return (static_cast<{}>(0));\n'.format(to_libpacket_enum_type(name, field)))


def write_to_libpacket_conversions(output, name, data):
    for field, props in filter(lambda kv: 'format' in kv[1] and kv[1]['format'] == 'enumeration', data.items()):
        if 'uniqueItems' in props:
            write_set_libpacket_enum_conversion(output, name, field, props)
        else:
            write_set_libpacket_flag_conversion(output, name, field, props)
        write_cr(output)


def has_defaults(data):
    return sum(list(map(lambda p: 1 if 'default' in p else 0, data.values()))) > 0

def write_to_libpacket_impl(output, name, data):
    format_dispatch = {
        'ipv4': write_set_libpacket_value_address,
        'ipv6': write_set_libpacket_value_address,
        'mac': write_set_libpacket_value_address,
        'enumeration': write_set_libpacket_value_enumeration
    }

    arg = 'src'
    output.write('{}\n'.format(to_libpacket_declaration(name, arg)))
    with cpp_scope(output) as f:
        f.write('auto dst = {}{{}};\n'.format(to_libpacket_object(name)))
        if has_defaults(data):
            f.write('set_{}_defaults(dst);\n'.format(name.lower()))
        write_cr(output)

        with cpp_scope(f, 'if ({}) {{'.format(arg)) as b:
            for field, props in data.items():
                if 'format' in props and props['format'] in format_dispatch:
                    writer = format_dispatch[props['format']]
                else:
                    writer = write_set_libpacket_value_default

                writer(b, arg, 'dst', name, field, props)

        write_cr(output)
        f.write('return (dst);\n')


def write_transmogrify_implementation(output, name, fields, header):
    write_file_header(output, name, "implementation")
    write_cr(output)

    output.write('#include "{}"\n'.format(header))
    write_cr(output)

    with cpp_namespace(output):
        write_to_swagger_impl(output, name, fields)
        write_cr(output)
        write_to_libpacket_conversions(output, name, fields)
        write_to_libpacket_impl(output, name, fields)


def main():
    parser = argparse.ArgumentParser(description="Generate swagger <-> libpacket transmogrify code")
    parser.add_argument('--infile',
                        nargs='?',
                        type=argparse.FileType('r'),
                        default=sys.stdin,
                        help="input YAML file containing protocol definition")
    parser.add_argument('--outdir',
                        nargs='?',
                        type=pathlib.Path,
                        default=os.getcwd(),
                        help="output directory to write generated files")

    args = parser.parse_args()

    if not os.path.isdir(args.outdir):
        sys.stderr.write('Output directory, {}, does not exist\n'.format(args.outdir))
        sys.exit(1)

    if not os.access(args.outdir, os.W_OK):
        sys.stderr.write('Output directory, {}, is not writable\n'.format(args.outdir))
        sys.exit(1)

    obj = yaml.load(args.infile, Loader=yaml.FullLoader)

    for name, data in obj.items():
        file_root = to_file_basename(name)
        header = file_root + '.hpp'

        fields = data['fields']

        with open(os.path.join(args.outdir, header), 'w') as header_out:
            write_transmogrify_header(header_out, name, fields)

        with open(os.path.join(args.outdir, file_root + '.cpp'), 'w') as impl_out:
            write_transmogrify_implementation(impl_out, name, fields, header)


if __name__ == "__main__":
    main()
