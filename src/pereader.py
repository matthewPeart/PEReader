#!/usr/bin/python
# -*- coding: utf-8 -*-
""" PEReader

 A feature-rich Python module for parsing Portable Executable files,
 that warns of PE file anomalies and malformations. The headers are
 accessible as exposed attributes (e.g. obj.DOS_HEADER). See the PE
 class definition for the list of all headers exposed as attributes.
 Containers improve the accessibility of the data directories. See
 inner classes to see which data directory containers are available.

 Examples:
    * Parse calc.exe from file -> pe = pereader.PE('calc.exe')

 Documentation:
    * https://github.com/matthewPeart/PEReader

    Copyright (c) 2020, Matthew Peart
"""

__author__ = 'Matthew Peart'
__version__ = '2020.08.09'

import collections
import hashlib
import time
import mmap
import math
import os

from typing import Dict, List, Union


# Formatting constants.
HEADER_LENGTH = 79
""" int: Length of header lines when formatting.
"""

COL_SPACE = 4
""" int: Space between columns when formatting.
"""

# Parser constants.
MAX_STRING_LENGTH = 0x100000
""" int: Limit length of strings (1 MB).
"""

MAX_SECTIONS = 0xFFFF
""" int: Limit number of sections.

    Corkami:
        -> Maximum NumberOfSections (Vista and later).
"""

MAX_SYMBOL_LENGTH = 0x200
""" int: Limit length of a symbol name.

    Corkami:
        -> Export names can actually be any length.
"""

MAX_EXPORTS = 0x2000
""" int: Limit number of exports.
"""

MAX_IMPORTS = 0x2000
""" int: Limit number of imports per DLL.
"""

MAX_DLLS = 0x1000
""" int: Limit number of imported DLLs.
"""

MAX_RESOURCE_ENTRIES = 0x1000
""" int : Limit number of resource entries.
"""

MAX_RELOCATIONS = 0x100
""" int: Limit number of relocation entries.
"""

MAX_RELOC_TARGETS = 0x2000

MAX_DEBUG = 0x100
""" int: Limit number of debug directories.
"""

# PE constants.
DOS_SIGNATURE = 0x5A4D
""" int: MS-DOS header magic.
"""

DOSZM_SIGNATURE = 0x4D5A
""" int: ZM-DOS header magic.
"""

NT_SIGNATURE = 0x4550
""" int: PE NT header signature.
"""

NT_OPTIONAL_HDR32_MAGIC = 0x10B
""" int: 32 bit optional header magic.
"""

NT_OPTIONAL_HDR64_MAGIC = 0x20B
""" int: 64 bit optional header magic.
"""

ROM_OPTIONAL_HDR_MAGIC = 0x107
""" int: ROM optional header magic.
"""

NUM_DATA_DIRECTORIES = 16
""" int: Standard number of data directories in PE files.
"""


class PEError(Exception):
    """ Generic exception for PE format errors.
    """

    def __init__(self, value: str) -> None:
        super().__init__()
        self.value = value

    def __str__(self) -> str:
        return repr(self.value)


class ParseError(Exception):
    """ Exception for Structure parsing errors.
    """

    def __init__(self, value: str) -> None:
        super().__init__()
        self.value = value

    def __str__(self) -> str:
        return repr(self.value)


class AttributeSetter():
    """ Inherited to make setting attributes easier.
    """

    def __init__(self, setter: Dict[str, str]) -> None:
        for k in setter:
            setattr(self, k, setter[k])


class Structure():
    """ Representation of a parsed winnt.h defined structure.

    Raises:
        ParseError: If unable to parse.
    """

    sizeof_types = {
        'b': 1,  # Byte.
        'A': 1,  # ASCII byte.
        'U': 1,  # Unicode byte.
        'w': 2,  # Word.
        'd': 4,  # Double word.
        't': 4,  # Timedate stamp.
        'u': 8,  # Quad word.
        'z': 12, # Three bytes.
        'g': 16  # GUID.
    }
    """ dict: size of winnt.h data types.
    """

    def __init__(
        self,
        image: List[tuple],
        name: str,
        data: bytes,
        offset: int,
        pad: int = 0
    ) -> None:

        self.raw = data
        """ bytes: Raw bytes of the structure.
        """

        self.sizeof = len(data)
        """ int: Stores the number of raw bytes parsed.
        """

        self.other = list()
        """ list of str: Stores names of set footnotes.
        """

        # Stores the structure type and fields.
        self.__type__ = name
        self.__keys__ = list()

        # Stores field values, file, and relative offsets.
        self.__file_offsets__ = dict()
        self.__rel_offsets__ = dict()
        self.__values__ = dict()

        # Stores maximum lengths for formatting.
        self._max_abs = 0
        self._max_rel = 0
        self._max_key = 0

        try:
            self.__parse__(image, offset, pad)

        except:
            raise ParseError("Unable to parse %s." % self.__type__)

    def __str__(self) -> str:
        """ [__type__]
            file_offset, rel_offset, field_name, value
            ...
            flags:
            ...
        """

        # Build the rows of the output.
        rows = list(map(lambda t: ''.join([
            hex(t[0]),
            ' ' * (self._max_abs + COL_SPACE - len(hex(t[0]))),
            hex(t[1]),
            ' ' * (self._max_rel + COL_SPACE - len(hex(t[1]))),
            t[2],
            ' ' * (self._max_key + COL_SPACE - len(t[2])),
            self._format_value(t[3])]), self.get_tuples()))

        # Add the structure flags.
        if hasattr(self, 'flags'):
            rows.append('\nflags:\n%s' % ',\n'.join(self.flags))

        # Add the footnotes.
        for entry in self.other:
            rows.append('\n%s: %s' % (entry, getattr(self, entry)))

        return '[%s]\n%s' % (self.__type__, '\n'.join(rows))

    def __repr__(self) -> str:
        """ <Structure: (file_offset, rel_offset, field_name, value), ...>
        """

        return '<Structure: %s>' % ', '.join(map(str, self.get_tuples()))

    def __parse__(
        self,
        image: List[tuple],
        offset: int,
        pad: int = 0
    ) -> None:
        """ Parses a winnt.h type from a given file offset.

        Raises:
            ParseError: If attempts to parse past eof.
        """

        # Add padding.
        data = self.raw + bytes(pad)

        p = 0

        for field in image:

            # Sizeof field type.
            size = self.sizeof_types[field[1]]

            if len(data[p:p+(size*field[2])]) != size * field[2]:
                raise ParseError("Tried to parse past eof.")

            # If an array store as bytes.
            if field[2] > 1:
                value = data[p:p+size*field[2]]

            else:

                # Otherwise unpack into unsigned integer.
                value = int.from_bytes(
                    data[p:p+size], byteorder='little')

            # To deal with unions we create multiple fields.
            for f in field[0].split('/'):
                self.set_field(f, offset+p, p, value, field[1])

            p += size * field[2]

    def _format_value(self, value: Union[bytes, int]) -> str:
        """ Formats value for printing.
        """

        if isinstance(value, bytes):
            return '[%s]' % ', '.join(map(hex, value))

        if isinstance(value, int):
            return hex(value)

        return str(value)

    def set_field(
        self,
        name: str,
        offset: int,
        relative: int,
        value: Union[int, bytes],
        encoding: chr = None
    ) -> None:
        """ Sets field in the structure with offsets and value.

        Raises:
            ValueError: If name is not unique.
        """

        if hasattr(self, name):
            raise ValueError('attribute already exists.')

        # Add the field to the structure.
        self.__keys__.append(name)
        self.__file_offsets__[name] = offset
        self.__rel_offsets__[name] = relative
        self.__values__[name] = value

        # Set value as an attribute.
        setattr(self, name, value)

        # Update maximum lengths for formatting.
        self._max_abs = max(len(hex(offset)), self._max_abs)
        self._max_rel = max(len(hex(relative)), self._max_rel)
        self._max_key = max(len(name), self._max_key)

        try:

            if encoding == 'A':
                decoded = bytes(value).decode('ascii').rstrip('\0')

            elif encoding == 'U':
                decoded = bytes(value).decode('utf-16le').rstrip('\0')

            elif encoding == 't':
                decoded = '[%s UTC]' % time.asctime(time.gmtime(value))

        except (AttributeError, OSError, TypeError, UnicodeDecodeError):
            decoded = '[INVALID]'

        # Set the footnote.
        if 'decoded' in locals():
            self.set_other('str_' + name, decoded)

    def set_other(self, name: str, value) -> None:
        """ Sets a footnote.

            Raises:
                ValueError: If name is not unique.
        """

        if hasattr(self, name):
            raise ValueError('attribute already exists.')

        setattr(self, name, value)

        self.other.append(name)

    def set_type(self, name: str) -> None:
        """ Sets the structure type.
        """

        self.__type__ = name

    def set_flags(self, characteristics: int, masks: list) -> None:
        """ Sets the flags as attributes of the structure.

            Raises:
                ValueError: If flag is not unique.
        """

        if not hasattr(self, 'flags'):
            self.flags = list()

        for mask in masks:

            if hasattr(self, mask[0]):
                raise ValueError('attribute already exists.')

            if bool(characteristics & mask[1]):
                setattr(self, mask[0], True)

                # Store flag in list.
                self.flags.append(mask[0])

            else:
                setattr(self, mask[0], False)

    def get_tuples(self) -> List[tuple]:
        """ Returns a list of tuples describing each field.
        """

        return list(map(lambda k: (
            self.__file_offsets__[k],
            self.__rel_offsets__[k],
            k,
            self.__values__[k]), self.__keys__))

    def get_type(self) -> str:
        """ Returns the structure type.
        """

        return self.__type__

    def get_file_offset(self, name: str) -> int:
        """ Returns the file offset of name.

        Raises:
            KeyError: If name doesn't exist.
        """

        if self.__values__.get(name) is None:
            raise KeyError("name does not exist.")

        return self.__file_offsets__.get(name)

    def get_relative_offset(self, name: str) -> int:
        """ Returns the relative offset of name.

        Raises:
            KeyError: If name doesn't exist.
        """

        if self.__values__.get(name) is None:
            raise KeyError("name does not exist.")

        return self.__rel_offsets__.get(name)

    def all_zeros(self) -> bool:
        """ Returns True if all fields are zero.
        """

        return all(self.__values__[k] == 0 for k in self.__values__)


class DataContainer(mmap.mmap):
    """ Container for file buffer.
    """

    def get_string_a(
        self,
        index: int,
        size: int = None,
        get_bytes: bool = False,
        max_length: int = MAX_STRING_LENGTH
    ) -> Union[str, bytes]:
        """ Returns ASCII string from data at index.
        """

        if size:

            # If size is specified.
            if size <= max_length:

                try:
                    decoded = self[index:index+size].decode('ascii')

                    if get_bytes:
                        return self[index:index+size]

                    return decoded

                except UnicodeDecodeError:
                    return None

            return None

        # Find the terminating character if no fixed size.
        null_byte = self.find(b'\0', index, index+max_length+1)

        if null_byte > 0:

            try:
                decoded = self[index:null_byte].decode('ascii')

                if get_bytes:
                    return self[index:null_byte]

                return decoded

            except UnicodeDecodeError:
                return None

    def get_string_u(
        self,
        index: int,
        size: int = None,
        get_bytes: bool = False,
        max_length: int = MAX_STRING_LENGTH
    ) -> Union[str, bytes]:
        """ Returns Unicode string from data at index.
        """

        if size:

            # If size is specified.
            if size <= max_length:

                try:
                    decoded = self[index:index+(size*2)].decode('utf-16le')

                    if get_bytes:
                        return self[index:index+(size*2)]

                    return decoded

                except UnicodeDecodeError:
                    return None

            return None

        p = index
        while p <= index + (max_length * 2) + 1:

            # Find the terminating character if no fixed size.
            null_byte = self.find(b'\0\0', p, index+(max_length*2)+1)

            if null_byte < 0:
                return None

            # Aligned on character boundary.
            if (null_byte - index) % 2 == 0:

                try:
                    decoded = self[index:null_byte].decode('utf-16le')

                except UnicodeDecodeError:
                    return None

                if get_bytes:
                    return self[index:null_byte]

                return decoded

            # Aligned between two characters so shift p.
            p = null_byte + 1

    def get_string_p(
        self,
        index: int,
        get_bytes: bool = False,
        max_length: int = MAX_STRING_LENGTH
    ) -> Union[str, bytes]:
        """ Returns Pascal string from data at index.
        """

        # Get number of bytes in string from the leading byte.
        length = int.from_bytes(self[index:index+2], byteorder='little') << 1

        if length <= max_length // 2:

            try:
                decoded = self[index+2:index+2+length].decode('utf-16le')

                if get_bytes:
                    return self[index+2:index+2+length]

                return decoded

            except UnicodeDecodeError:
                return None

    def get_hashes(
        self,
        algs: list = ['md5', 'sha1', 'sha256', 'sha512']
    ) -> Dict[str, str]:
        """ Returns a dictionary of hashes specified by algs.
        """

        hashes = dict()

        for alg in algs:
            hashes[alg] = getattr(hashlib, alg)(self).hexdigest()

        return hashes

    def length_until_eof(self, index: int) -> int:
        """ Returns the number of bytes left before reaching eof.
        """

        return len(self) - index

    def get_entropy(self, index: int, size: int) -> float:
        """ Returns the entropy from data at index.
        """

        if size <= 0 or len(self[index:index+size]) == 0:
            return 0

        count = collections.Counter(self[index:index+size])

        # Calculate the entropy.
        return sum(map(
            lambda b: -((float(b) / size) * math.log(float(b) / size, 2)),
            count.values()))


class ExportSymbols():
    """ Representation of exported symbols.
    """

    Symbol = type('Symbol', (AttributeSetter,), {})
    """ class: Representation of a symbol.
    """

    def __init__(self) -> None:

        self.symbols = list()
        """ list of Symbol: Stores the export symbols.
        """

        # Stores maximum lengths for formatting.
        self._max_ord = 7
        self._max_add = 3

    def __str__(self) -> str:
        """ ordinal, address, name, forwarder.
            ...
        """

        # Build the table header string.
        header = 'Ordinal%sRVA%sName' % (
            ' ' * (self._max_ord + COL_SPACE - 7),
            ' ' * (self._max_add + COL_SPACE - 3))

        # Build the rows of the output.
        rows = map(lambda s: ''.join([
            str(s.ordinal),
            ' ' * (self._max_ord + COL_SPACE - len(str(s.ordinal))),
            hex(s.address),
            ' ' * (self._max_add + COL_SPACE - len(hex(s.address))),
            str(s.name),
            ' ',
            self._format_forwarder(s.forwarder)]), self.symbols)

        return '%s\n%s' % (header, '\n'.join(rows))

    def __repr__(self) -> str:
        """ <ExportSymbols: (ordinal, address, name, forwarder), ...>
        """

        return '<ExportSymbols: %s>' % ', '.join(map(str, self.get_tuples()))

    def __getitem__(self, index: int) -> Symbol:
        return self.symbols[index]

    def _format_forwarder(self, value: str) -> str:
        """ Formats a forwarder value.
        """

        return 'forwarder: %s' % value if value else ''

    def set_symbol(
        self,
        ordinal: int,
        address: int,
        name: str = None,
        forwarder: str = None
    ) -> None:
        """ Sets a symbol.
        """

        # Create the symbol.
        self.symbols.append(ExportSymbols.Symbol({
            'ordinal': ordinal,
            'address': address,
            'name': name,
            'forwarder': forwarder}))

        # Set the address as an attribute.
        if name:
            setattr(self, name, address)

        # Update maximum lengths.
        self._max_ord = max(len(str(ordinal)), self._max_ord)
        self._max_add = max(len(hex(address)), self._max_add)

    def get_tuples(self) -> List[tuple]:
        """ Returns a list of tuples of each symbol.
        """

        return list(map(lambda s: (
            s.ordinal,
            s.address,
            s.name,
            s.forwarder), self.symbols))


class ImportSymbols():
    """ Representation of imported symbols.
    """

    Symbol = type('Symbol', (AttributeSetter,), {})
    """ class: Representation of a symbol.
    """

    def __init__(
        self,
        descriptor: Structure,
        name: str,
        is_bound: bool
    ) -> None:

        self.symbols = list()
        """ list of Symbol: Stores the import symbols.
        """

        self.IMPORT_DESCRIPTOR = descriptor
        """ Structure: The import descriptor.
        """

        self.name = name
        """ str: Name of the DLL.
        """

        self.is_bound = is_bound
        """ bool: True if bound.
        """

    def __str__(self) -> str:
        """ <ImportSymbols>
            name.function_name Hint[hint] Bound: address.
            ...
        """

        # Build the rows of the output.
        rows = map(lambda s: '%s.%s Hint[%s] %s' % (
            self.name,
            str(s.name),
            str(s.hint),
            self._format_address(s.address)), self.symbols)

        return '%s\n\n<ImportSymbols>\n%s' % (
            self.IMPORT_DESCRIPTOR.__str__(), '\n'.join(rows))

    def __repr__(self) -> str:
        """ <ImportSymbols: (function_name, hint, address), ...>
        """

        return '<ImportSymbols: %s>' % ', '.join(map(str, self.get_tuples()))

    def __getitem__(self, index: int) -> Symbol:
        return self.symbols[index]

    def _format_address(self, value: str) -> str:
        """ Formats an address value if bound.
        """

        return 'bound: %s' % hex(value) if self.is_bound else ''

    def set_symbol(self, hint: int, name: str, address: int) -> None:
        """ Sets a symbol in the DLL.
        """

        # Create the symbol.
        self.symbols.append(ImportSymbols.Symbol({
            'hint': hint,
            'name': name,
            'address': address}))

        # Set the address as an attribute.
        if name:
            setattr(self, name, address)

    def get_tuples(self) -> List[tuple]:
        """ Returns a list of tuples of each symbol.
        """

        return list(map(lambda s: (
            s.name,
            s.hint,
            s.address), self.symbols))


class VersionInformation():
    """ Representation of version information.
    """

    StringFileInfo = type('StringFileInfo', (AttributeSetter,), {})
    """ class: Representation of a StringFileInfo.
    """

    VarFileInfo = type('VarFileInfo', (AttributeSetter,), {})
    """ class: Representation of a VarFileInfo.
    """

    def __init__(
        self,
        versioninfo: Structure,
        fixedfileinfo: Structure = None
    ) -> None:

        self.VS_VERSIONINFO = versioninfo
        """ Structure: Version information structure.
        """

        self.VS_FIXEDFILEINFO = fixedfileinfo
        """ Structure: Fixed file information structure.
        """

        self.stringfileinfo = list()
        """ list of StringFileInfo: Contains string tables.
        """

        self.varfileinfo = list()
        """ list of VarFileInfo: Contains vars.
        """

    def __str__(self) -> str:

        builder = list()

        # Add version information.
        builder.append(self.VS_VERSIONINFO.__str__())

        # Add fixed file information.
        if self.VS_FIXEDFILEINFO:
            builder.append(self.VS_FIXEDFILEINFO.__str__())

        # Add string file information.
        for entry in self.stringfileinfo:
            builder.append(entry.STRINGFILEINFO.__str__())

            for stringtable in entry.stringtables:
                builder.append(stringtable.STRINGTABLE.__str__())

                rows = list()
                for string in stringtable.strings:
                    rows.append('%s: %s' % (string.str_szKey, string.str_Value))

                builder.append('\n'.join(rows))

        # Add var file information.
        for entry in self.varfileinfo:
            builder.append(entry.VARFILEINFO.__str__())

            for var in entry.vars:
                builder.append(var.VAR.__str__())

                rows = list()
                for w1, w2 in var.translations:
                    rows.append("Translation: 0x%04x 0x%04x" % (w1, w2))

                builder.append('\n'.join(rows))

        return '\n\n'.join(builder)

    def set_stringfileinfo(
        self,
        stringfileinfo: Structure,
        stringtable: list
    ) -> None:
        """ Sets a StringFileInfo entry.
        """

        # Create the StringFileInfo.
        self.stringfileinfo.append(VersionInformation.StringFileInfo({
            'STRINGFILEINFO': stringfileinfo,
            'stringtables': stringtable}))

    def set_varfileinfo(
        self,
        varfileinfo: Structure,
        var: list
    ) -> None:
        """ Sets a VarFileInfo entry.
        """

        # Create the VarFileInfo.
        self.varfileinfo.append(VersionInformation.VarFileInfo({
            'VARFILEINFO': varfileinfo,
            'vars': var}))


class PE():
    """ Representation of portable executable file.

    Raises:
        ValueError: If fname is not specified.
        IOError: If unable to read file.
        IOError: If file is empty.
    """

    class ExportContainer():
        """ Container for export directory information.
        """

        __IMAGE_EXPORT_DIRECTORY__ = [
            ('Characteristics',       'd',  1),
            ('TimeDateStamp',         't',  1),
            ('MajorVersion',          'w',  1),
            ('MinorVersion',          'w',  1),
            ('Name',                  'd',  1),
            ('Base',                  'd',  1),
            ('NumberOfFunctions',     'd',  1),
            ('NumberOfNames',         'd',  1),
            ('AddressOfFunctions',    'd',  1),
            ('AddressOfNames',        'd',  1),
            ('AddressOfNameOrdinals', 'd',  1)
        ]
        """ list of tuple: winnt.h definition of export directory.
        """

        def __init__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:

            self.EXPORT_DIRECTORY = None
            """ Structure: Export directory.
            """

            self.address_of_function = list()
            """ list of int: Rva's to functions.
            """
            self.address_of_name = list()
            """ list of int: Rva's to names.
            """
            self.name_ordinal = list()
            """ list of int: Name ordinal table.
            """

            self.symbols = ExportSymbols()
            """ ExportSymbols: Export symbols.
            """

            self.__parse__(outer, data, directory)

        def __str__(self) -> str:
            return '%s\n\n%s' % (
                self.EXPORT_DIRECTORY.__str__(),
                self.symbols.__str__())

        def __parse__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:
            """ Parses export information.
            """

            # We check for duplicate export symbols to prevent some
            # malformations where some function rva's are repeated.
            counts = collections.Counter()

            p = outer.rva_to_file_offset(directory.VirtualAddress)

            try:

                self.EXPORT_DIRECTORY = Structure(
                    self.__IMAGE_EXPORT_DIRECTORY__,
                    'IMAGE_EXPORT_DIRECTORY',
                    data[p:p+40],
                    p)

            except ParseError:
                outer.warnings.append(
                    "Unable to parse IMAGE_EXPORT_DIRECTORY.")

                return None

            try:

                p = outer.rva_to_file_offset(
                    self.EXPORT_DIRECTORY.AddressOfFunctions)

                # Set a maximum number of functions using eof.
                number_of_functions = min(
                    self.EXPORT_DIRECTORY.NumberOfFunctions,
                    data.length_until_eof(p) // 4,
                    MAX_EXPORTS)

                # Check for anomalous number of exports.
                if number_of_functions == MAX_EXPORTS:
                    outer.warnings.append(
                        "NumberOfFunctions is bigger than the parser limit. "
                        "Some exports are not parsed.")

                elif number_of_functions == data.length_until_eof(p) // 4:
                    outer.warnings.append(
                        "address_of_function extends beyond eof.")

                size = number_of_functions * 4

                self.address_of_function = list(
                    map(lambda x: int.from_bytes(x, byteorder='little'),
                        [data[p+i:p+i+4] for i in range(0, size, 4)]))

                p = outer.rva_to_file_offset(
                    self.EXPORT_DIRECTORY.AddressOfNames)

                # Can't have more names than functions.
                number_of_names = min(
                    self.EXPORT_DIRECTORY.NumberOfNames,
                    data.length_until_eof(p) // 4,
                    number_of_functions)

                # Check for anomalous number of names.
                if self.EXPORT_DIRECTORY.NumberOfNames > number_of_functions:
                    outer.warnings.append(
                        "NumberOfNames is bigger than the parser limit. "
                        "Some export names are not parsed.")

                elif number_of_names == data.length_until_eof(p) // 4:
                    outer.warnings.append(
                        "address_of_name extends beyond eof.")

                size = number_of_names * 4

                self.address_of_name = list(
                    map(lambda x: int.from_bytes(x, byteorder='little'),
                        [data[p+i:p+i+4] for i in range(0, size, 4)]))

                # TODO: Make sure AddressOfNames is lexicographically-ordered.

                p = outer.rva_to_file_offset(
                    self.EXPORT_DIRECTORY.AddressOfNameOrdinals)

                # Use remaining size of file as upper bound.
                size = min(number_of_names * 2, data.length_until_eof(p))

                # Check for anomalous number of ordinals.
                if size == data.length_until_eof(p):
                    outer.warnings.append(
                        "name_ordinal extends beyond eof.")

                self.name_ordinal = list(
                    map(lambda x: int.from_bytes(x, byteorder='little'),
                        [data[p+i:p+i+2] for i in range(0, size, 2)]))

            except:
                outer.warnings.append(
                    "Unable to parse export directory tables.")

                return None

            # Create index -> name translation table.
            index_name = dict()
            for idx in range(len(self.name_ordinal)):
                index_name[self.name_ordinal[idx]] = idx

            maximum_failures = 5
            for idx in range(number_of_functions):

                # Determine ordinal and address.
                ordinal = idx + self.EXPORT_DIRECTORY.Base
                address = self.address_of_function[idx]

                # Symbol doesn't exist for idx.
                if address == 0:
                    continue

                try:

                    # Retrieve the name from data.
                    name = data.get_string_a(
                        outer.rva_to_file_offset(
                            self.address_of_name[index_name[idx]]),
                        max_length=MAX_SYMBOL_LENGTH)

                    # Check if parsing was successful.
                    if name is None:
                        outer.warnings.append(
                            "Unable to parse export name.")

                        maximum_failures -= 1
                        if maximum_failures == 0:
                            break

                except KeyError:

                    # Import by ordinal only.
                    name = None

                # If address points within the export directory it points
                # to a string with the forwarded symbol's string, else it
                # points to the start of the function (i.e start address).
                if directory.VirtualAddress < address \
                    < directory.VirtualAddress + directory.Size:

                    # Retrieve the forwarder string.
                    forwarder_str = data.get_string_a(
                        outer.rva_to_file_offset(address))

                    # Check if parsing was successful.
                    if forwarder_str is None:
                        outer.warnings.append(
                            "Unable to parse export forwarder string.")

                        maximum_failures -= 1
                        if maximum_failures == 0:
                            break

                else:
                    forwarder_str = None

                # Add the export symbol.
                self.symbols.set_symbol(
                    ordinal,
                    address,
                    name,
                    forwarder_str)

                counts[(name, address)] += 1

                if counts[(name, address)] > 5:
                    outer.warnings.append(
                        "Exports contains repeated entries. "
                        "Stopped parsing the export directory.")

                    break

            if maximum_failures == 0:
                outer.warnings.append(
                    "Hit maximum number of failures. "
                    "Stopped parsing the export directory.")


    class ImportBaseClass():
        """ A base class for parsing import information.
        """

        __IMAGE_THUNK_DATA32__ = [
            ('ForwarderString/Function/Ordinal/AddressOfData', 'd', 1)
        ]
        """ list of tuple: winnt.h definition of 32 bit thunk data.
        """

        __IMAGE_THUNK_DATA64__ = [
            ('ForwarderString/Function/Ordinal/AddressOfData', 'u', 1)
        ]
        """ list of tuple: winnt.h definition of 64 bit thunk data.
        """

        __IMAGE_IMPORT_BY_NAME__ = [
            ('Hint', 'w', 1),
            ('Name', 'b', 1)
        ]
        """ list of tuple: winnt.h definition of import by name.
        """

        def __init__(self) -> None:

            self.address_table = list()
            """ list of Structure: THUNK_DATA structures.
            """

            self.name_table = list()
            """ list of Structure: THUNK_DATA structures.
            """

            self.dlls = list()
            """ list of ImportSymbols: Import symbols.
            """

        def parse_table(
            self,
            outer,
            data: DataContainer,
            rva: int
        ) -> List[Structure]:
            """ Parses an import address or import name table.
            """

            table = list()

            if outer.pe_type == 0x10b:
                thunk_type = self.__IMAGE_THUNK_DATA32__
                thunk_name = 'IMAGE_THUNK_DATA32'
                size = 4

            elif outer.pe_type == 0x20b:
                thunk_type = self.__IMAGE_THUNK_DATA64__
                thunk_name = 'IMAGE_THUNK_DATA64'
                size = 8

            p = outer.rva_to_file_offset(rva)

            # Set a maximum number of functions.
            max_iterations = min(
                data.length_until_eof(p) // size,
                MAX_IMPORTS)

            for _ in range(max_iterations):

                try:

                    thunk = Structure(
                        thunk_type,
                        thunk_name,
                        data[p:p+size],
                        p)

                except ParseError:
                    outer.warnings.append(
                        "Unable to parse %s." % thunk_name)

                    break

                # Check for null terminating thunk.
                if thunk.all_zeros():
                    break

                table.append(thunk)

                p += size

            else:
                outer.warnings.append(
                    "Anomalous number of IMAGE_THUNK_DATA. "
                    "Some imports are not parsed.")

            return table

        def create_dll(
            self,
            outer,
            data: DataContainer,
            descriptor: Structure,
            dll_name: str,
            is_bound: bool,
            addresses: List[Structure],
            names: List[Structure]
        ) -> ImportSymbols:
            """ Creates a DLL representation of an import.
            """

            max_failures = 10

            if outer.pe_type == 0x10b:
                ordinal_flag = 0x80000000

            elif outer.pe_type == 0x20b:
                ordinal_flag = (2 ** ((8 * 8) - 1))

            # If the time-date stamp is 0, then the imports are not
            # bound, but if -1, the imports of the DLL are bounded.
            dll = ImportSymbols(descriptor, dll_name, is_bound)

            # Add the symbols to the DLL. If addresses and names do
            # not have an equal # of thunks due to breaking, we can
            # still maximise the # of symbols parsed by using zip.
            for address_thunk, name_thunk in zip(addresses, names):

                # If the MSB bit of the name thunk is set then there
                # is no symbol name & is imported purely by ordinal.
                if name_thunk.Ordinal & ordinal_flag:

                    # Lowest 16 bits contain hint value.
                    hint = name_thunk.Ordinal & 0xFFFF

                    # Import has no name.
                    name = None

                else:

                    # Contains rva to import by name.
                    p = outer.rva_to_file_offset(
                        name_thunk.AddressOfData)

                    try:

                        import_by_name = Structure(
                            self.__IMAGE_IMPORT_BY_NAME__,
                            'IMAGE_IMPORT_BY_NAME',
                            data[p:p+3],
                            p)

                    except ParseError:
                        outer.warnings.append(
                            "Unable to parse IMAGE_IMPORT_BY_NAME.")

                        max_failures -= 1
                        if max_failures < 0:
                            break

                        continue

                    # Get the hint.
                    hint = import_by_name.Hint

                    # Get the name.
                    name = data.get_string_a(
                        outer.rva_to_file_offset(
                            name_thunk.AddressOfData+2),
                        max_length=MAX_SYMBOL_LENGTH)

                    # Check if parsing was successful.
                    if name is None:
                        outer.warnings.append(
                            "Unable to parse import symbol name.")

                        max_failures -= 1
                        if max_failures < 0:
                            break

                dll.set_symbol(hint, name, address_thunk.Function)

            if max_failures < 0:
                outer.warnings.append(
                    "Hit maximum number of failures. "
                    "Stopped parsing imported DLL.")

            return dll


    class ImportContainer(ImportBaseClass):
        """ Container for import directory information.
        """

        __IMAGE_IMPORT_DESCRIPTOR__ = [
            ('Characteristics/OriginalFirstThunk', 'd', 1),
            ('TimeDateStamp',                      't', 1),
            ('ForwarderChain',                     'd', 1),
            ('Name',                               'd', 1),
            ('FirstThunk',                         'd', 1)
        ]
        """ list of tuple: winnt.h definition of import descriptor.
        """

        def __init__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:

            super().__init__()

            self.__parse__(outer, data, directory)

        def __str__(self) -> str:
            return '\n\n'.join(
                map(lambda d: d.__str__(), self.dlls))

        def __parse__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:
            """ Parses import information.
            """

            p = outer.rva_to_file_offset(directory.VirtualAddress)

            # Set a maximum number of import descriptors.
            number_of_descriptors = min(
                data.length_until_eof(p) // 20,
                MAX_DLLS)

            maximum_failures = 5
            for _ in range(number_of_descriptors):

                try:

                    descriptor = Structure(
                        self.__IMAGE_IMPORT_DESCRIPTOR__,
                        'IMAGE_IMPORT_DESCRIPTOR',
                        data[p:p+20],
                        p)

                except ParseError:
                    outer.warnings.append(
                        "Unable to parse IMAGE_IMPORT_DESCRIPTOR.")

                    break

                # Check for null terminating descriptor.
                if descriptor.all_zeros():
                    break

                # Parse the import address table.
                addresses = self.parse_table(
                    outer, data, descriptor.FirstThunk)

                self.address_table.append(addresses)

                # Parse the import name table.
                names = self.parse_table(
                    outer, data, descriptor.OriginalFirstThunk)

                self.name_table.append(names)

                # Get the dll name.
                dll_name = data.get_string_a(
                    outer.rva_to_file_offset(
                        descriptor.Name),
                    max_length=MAX_SYMBOL_LENGTH)

                # Check if parsing was successful.
                if dll_name is None:
                    outer.warnings.append(
                        "Unable to parse DLL name.")

                    maximum_failures -= 1
                    if maximum_failures < 0:
                        break

                descriptor.set_other('str_Name', dll_name)

                # Construct the dll.
                dll = self.create_dll(
                    outer,
                    data,
                    descriptor,
                    dll_name,
                    bool(descriptor.TimeDateStamp),
                    addresses,
                    names)

                # Append the dll.
                self.dlls.append(dll)

                p += 20

            else:
                outer.warnings.append(
                    "Anomalous number of import descriptors. "
                    "Some imported DLLs are not parsed.")

            if maximum_failures < 0:
                outer.warnings.append(
                    "Hit maximum number of failures. "
                    "Stopped parsing the import directory.")


    class ResourceContainer():
        """ Container for resource directory information.
        """

        Directory = type('Directory', (AttributeSetter,), {})
        """ class: Representation of a directory.
        """

        Entry = type('Entry', (AttributeSetter,), {})
        """ class: Representation of an entry.
        """

        StringTable = type('StringTable', (AttributeSetter,), {})
        """ class: Representation of a string table.
        """

        Var = type('Var', (AttributeSetter,), {})
        """ class: Representation of a var.
        """

        __IMAGE_RESOURCE_DIRECTORY__ = [
            ('Characteristics',      'd', 1),
	    ('TimeDateStamp',        't', 1),
            ('MajorVersion',         'w', 1),
            ('MinorVersion',         'w', 1),
            ('NumberOfNamedEntries', 'w', 1),
            ('NumberOfIdEntries',    'w', 1)
        ]
        """ list of tuple: winnt.h definition of resource directory.
        """

        __IMAGE_RESOURCE_DIRECTORY_ENTRY__ = [
            ('Name',         'd', 1),
            ('OffsetToData', 'd', 1)
        ]
        """ list of tuple: winnt.h definition of resource directory entry.
        """

        __IMAGE_RESOURCE_DATA_ENTRY__ = [
            ('OffsetToData', 'd', 1),
            ('Size',         'd', 1),
            ('CodePage',     'd', 1),
            ('Reserved',     'd', 1)
        ]
        """ list of tuple: winnt.h definition of resource data entry.
        """

        __RESOURCE_TYPE__ = {
            1:  'RT_CURSOR',
            2:  'RT_BITMAP',
            3:  'RT_ICON',
            4:  'RT_MENU',
            5:  'RT_DIALOG',
            6:  'RT_STRING',
            7:  'RT_FONTDIR',
            8:  'RT_FONT',
            9:  'RT_ACCELERATOR',
            10: 'RT_RCDATA',
            11: 'RT_MESSAGETABLE',
            12: 'RT_GROUP_CURSOR',
            14: 'RT_GROUP_ICON',
            16: 'RT_VERSION',
            17: 'RT_DLGINCLUDE',
            19: 'RT_PLUGPLAY',
            20: 'RT_VXD',
            21: 'RT_ANICURSOR',
            22: 'RT_ANIICON',
            23: 'RT_HTML',
            24: 'RT_MANIFEST'
        }
        """ dict: Resource types.
        """

        __VS_VERSIONINFO__ = [
            ('wLength',      'w', 1),
            ('wValueLength', 'w', 1),
            ('wType',        'w', 1),
            ('szKey',        'U', 32)
        ]
        """ list of tuple: definition of version information.
        """

        __VS_FIXEDFILEINFO__ = [
            ('Signature',        'd', 1),
            ('StrucVersion',     'd', 1),
            ('FileVersionMS',    'd', 1),
            ('FileVersionLS',    'd', 1),
            ('ProductVersionMS', 'd', 1),
            ('ProductVersionLS', 'd', 1),
            ('FileFlagsMask',    'd', 1),
            ('FileFlags',        'd', 1),
            ('FileOS',           'd', 1),
            ('FileType',         'd', 1),
            ('FileSubtype',      'd', 1),
            ('FileDateMS',       'd', 1),
            ('FileDateLS',       'd', 1)
        ]
        """ list of tuple: definition of fixed file information.
        """

        __STRINGFILEINFO__ = [
            ('wLength',     'w', 1),
            ('ValueLength', 'w', 1),
            ('Type',        'w', 1),
            ('szKey',       'U', 30)
        ]
        """ list of tuple: definition of string file information.
        """

        __STRINGTABLE__ = [
            ('wLength',      'w', 1),
            ('wValueLength', 'w', 1),
            ('wType',        'w', 1),
            ('szKey',        'U', 18)
        ]
        """ list of tuple: definition of string table.
        """

        __STRING__ = [
            ('wLength',      'w', 1),
            ('wValueLength', 'w', 1),
            ('wType',        'w', 1)
        ]
        """ list of tuple: definition of string.
        """

        __VARFILEINFO__ = [
            ('wLength',     'w', 1),
            ('ValueLength', 'w', 1),
            ('Type',        'w', 1),
            ('szKey',       'U', 24)
        ]
        """ list of tuple: definition of variable file information.
        """

        __VAR__ = [
            ('wLength',      'w', 1),
            ('wValueLength', 'w', 1),
            ('wType',        'w', 1),
            ('szKey',        'U', 24)
        ]
        """ list of tuple: definition of var.
        """

        def __init__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:

            self.resource_directory = None
            """ Structure: The root RESOURCE_DIRECTORY.
            """

            self.__parse__(outer, data, directory)

        def __str__(self) -> str:
            builder = list()

            # Stack used in depth-first search.
            stack = [self.resource_directory]

            while stack:
                e = stack.pop()

                if isinstance(e, Structure):
                    builder.append(e.__str__())

                    # If the data entry has strings.
                    if hasattr(e, 'strings'):
                        rows = '\n'.join(
                            ['%d: %s' % (k, repr(e.strings[k]))
                             for k in e.strings])

                        builder.append("[Strings]\n%s" % rows)

                    # If the data entry has version information.
                    if hasattr(e, 'version'):
                        builder.append(e.version.__str__())

                elif type(e).__name__ == 'Directory':
                    builder.append(e.RESOURCE_DIRECTORY.__str__())

                    # Add the entries to the stack.
                    stack.extend(e.entries[::-1])

                elif type(e).__name__ == 'Entry':
                    builder.append(e.RESOURCE_DIRECTORY_ENTRY.__str__())

                    # Add the directory / entry to the stack.
                    stack.append(e.data)

            return '%s' % '\n\n'.join(builder)

        def __parse__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:
            """ Parses resources information.
            """

            # We count the rva's of directories already seen to detect a
            # recursive looping malformation, where entries have offsets
            # to an already parsed directory, creating an infinite loop.
            self.counts = collections.Counter()

            # Recursively parse from the root directory.
            self.resource_directory = self._parse_directory(
                outer,
                data,
                directory.VirtualAddress,
                directory.VirtualAddress)

        def _parse_directory(
            self,
            outer,
            data: DataContainer,
            rva: int,
            base_rva: int,
            level: int = 0
        ) -> type:
            """ Parses a resource directory.
            """

            self.counts[rva] += 1

            if self.counts[rva] > 1:
                outer.warnings.append(
                    "Resources contains recursive directories. "
                    "Stopped parsing the directory.")

                return None

            p = outer.rva_to_file_offset(rva)

            try:

                directory = Structure(
                    self.__IMAGE_RESOURCE_DIRECTORY__,
                    'IMAGE_RESOURCE_DIRECTORY',
                    data[p:p+16],
                    p)

            except ParseError:
                outer.warnings.append(
                    "Unable to parse IMAGE_RESOURCE_DIRECTORY.")

                return None

            directory.set_other('int_Level', level)

            entries = list()

            # Set a maximum number of entries using eof.
            number_of_entries = min(
                directory.NumberOfNamedEntries + \
                    directory.NumberOfIdEntries,
                data.length_until_eof(p) // 8,
                MAX_RESOURCE_ENTRIES)

            # Check for anomalous number of resource entries.
            if number_of_entries == MAX_RESOURCE_ENTRIES:
                outer.warnings.append(
                    "Number of resource entries is bigger than the "
                    "parser limit. Some resource entries are not parsed.")

            elif number_of_entries == data.length_until_eof(p) // 8:
                outer.warnings.append(
                    "Resource entries extends beyond eof.")

            # Immediately following the resource directory is an array
            # of a few resource directory entry structures, with named
            # entries first, immediately followed by some ID entries.
            for idx in range(number_of_entries):

                entry = self._parse_resource_entry(
                    outer,
                    data,
                    p + 16 + (8 * idx),
                    base_rva,
                    level)

                if entry is None:
                    break

                entries.append(entry)

            return PE.ResourceContainer.Directory({
                'RESOURCE_DIRECTORY': directory,
                'entries': entries})

        def _parse_resource_entry(
            self,
            outer,
            data: DataContainer,
            offset: int,
            base_rva: int,
            level: int
        ) -> type:
            """ Parses a resource entry.
            """

            p = offset

            try:

                entry = Structure(
                    self.__IMAGE_RESOURCE_DIRECTORY_ENTRY__,
                    'IMAGE_RESOURCE_DIRECTORY_ENTRY',
                    data[p:p+8],
                    p)

            except ParseError:
                outer.warnings.append(
                    "Unable to parse IMAGE_RESOURCE_DIRECTORY_ENTRY.")

                return None

            # First bit indicates whether entry has a name.
            is_name = entry.Name & 0x80000000

            # Last bits are an offset to name or Id.
            name_offset = entry.Name & 0x7FFFFFFF
            Id = entry.Name & 0x0000FFFF

            # First bit indicates whether offset is a directory.
            is_directory = entry.OffsetToData & 0x80000000

            # Last bits are an offset to directory / data entry.
            data_offset = entry.OffsetToData & 0x7FFFFFFF

            # If the MSB of Name field is set, the other 31 bits are
            # an offset to a string which is a name of the resource.
            # If the MSB is not set, the lower 16 bits create an ID.
            # The offset is from the beginning of the .rsrc section.
            if is_name:

                name = data.get_string_p(
                    outer.rva_to_file_offset(
                        base_rva + name_offset))

                # Check if parsing was successful.
                if name is None:
                    outer.warnings.append(
                        "Unable to parse resource entry name.")

                entry.set_other('str_Name', name)

            else:
                entry.set_other('int_Id', Id)

                if level == 0:

                    try:
                        rsrc_type = self.__RESOURCE_TYPE__[Id]

                    except KeyError:
                        outer.warnings.append(
                            "Resource type unknown.")

                        rsrc_type = None

                    entry.set_other('str_Type', rsrc_type)

            # If the MSB of offset is set, the other 31 bits are an
            # offset to another resource directory. If it isn't set
            # the remaining 31 bits are an offset to the rsrc data.
            # The offset is from the beginning of the rsrc section.
            if is_directory:

                parsed_data = self._parse_directory(
                    outer,
                    data,
                    base_rva + data_offset,
                    base_rva,
                    level+1)

                if parsed_data is None:
                    outer.warnings.append(
                        "Unable to parse resource directory.")

                    return None

                # Parse the string table.
                if hasattr(entry, 'str_Type') and entry.str_Type == 'RT_STRING':
                    strings = dict()

                    # Loop through each NameID entry.
                    for name_id in parsed_data.entries:

                        if name_id is None:
                            continue

                        if name_id.is_directory:

                            # Loop through each Lang entry.
                            for lang in name_id.data.entries:

                                if lang is None:
                                    continue

                                tag = name_id.RESOURCE_DIRECTORY_ENTRY.int_Id
                                tag = (tag - 1) * 16

                                lang_strings = self._get_resource_strings(
                                    data,
                                    outer.rva_to_file_offset(
                                        lang.data.OffsetToData),
                                    lang.data.Size,
                                    tag)

                                lang.data.strings = lang_strings

                                # Update the shortcut table.
                                strings.update(lang_strings)

                # Parse version information.
                if hasattr(entry, 'str_Type') and entry.str_Type == 'RT_VERSION':

                    # Loop through each NameID entry.
                    for name_id in parsed_data.entries:

                        if name_id is None:
                            continue

                        if name_id.is_directory:

                            # Loop through each Lang entry.
                            for lang in name_id.data.entries:

                                if lang is None:
                                    continue

                                vs = self._get_version_information(
                                    outer,
                                    data,
                                    lang.data.OffsetToData)

                                lang.data.version = vs

            else:

                p = outer.rva_to_file_offset(
                    base_rva + data_offset)

                try:

                    parsed_data = Structure(
                        self.__IMAGE_RESOURCE_DATA_ENTRY__,
                        'IMAGE_RESOURCE_DATA_ENTRY',
                        data[p:p+16],
                        p)

                except ParseError:
                    outer.warnings.append(
                        "Unable to parse IMAGE_RESOURCE_DATA_ENTRY.")

                    return None

            e = PE.ResourceContainer.Entry({
                'RESOURCE_DIRECTORY_ENTRY': entry,
                'data': parsed_data,
                'is_name': is_name,
                'is_directory': is_directory})

            # Create shortcuts to resource data.
            if hasattr(entry, 'str_Type') and entry.str_Type == 'RT_STRING':
                if 'strings' in locals():
                    e.strings = strings

            if hasattr(entry, 'str_Type') and entry.str_Type == 'RT_VERSION':
                if 'vs' in locals():
                    e.version = vs

            return e

        def _get_resource_strings(
            self,
            data: DataContainer,
            offset: int,
            size: int,
            tag: int
        ) -> dict:
            """ Returns resource strings.
            """

            strings = dict()

            # Relative pointer.
            p = 0

            while p + 2 <= size:

                # Get the size of the next string.
                length = int.from_bytes(
                    data[offset+p:offset+p+2], byteorder='little')

                p += 2

                if length == 0:
                    continue

                if 0 < p + length <= size:

                    # Read the unicode string.
                    s = data.get_string_u(offset+p, length)

                    if s:
                        strings[tag] = s

                p += length * 2

                tag += 1

            return strings

        def _get_version_information(
            self,
            outer,
            data: DataContainer,
            base_rva: int,
        ) -> VersionInformation:
            """ Returns version information.
            """

            # File offset of version information base.
            offset = outer.rva_to_file_offset(base_rva)

            p = offset

            try:

                vs_info = Structure(
                    self.__VS_VERSIONINFO__,
                    'VS_VERSIONINFO',
                    data[p:p+38],
                    p)

                if vs_info.str_szKey != 'VS_VERSION_INFO':
                    raise ParseError(
                        "szKey does not match VS_VERSIONINFO.")

            except ParseError:
                outer.warnings.append(
                    "Unable to parse VS_VERSIONINFO.")

                return None

            # Padding1 to align on 32-bit relative boundary.
            p += 38 + (base_rva + (p - offset) + 38) % 4

            if vs_info.wValueLength:

                try:

                    vs_fixedfileinfo = Structure(
                        self.__VS_FIXEDFILEINFO__,
                        'VS_FIXEDFILEINFO',
                        data[p:p+52],
                        p)

                except ParseError:
                    outer.warnings.append(
                        "Unable to parse VS_FIXEDFILEINFO.")

                    return None

                # Padding2 to align on 32-bit relative boundary.
                p += 52 + (base_rva + (p - offset) + 52) % 4

            else:
                outer.warnings.append(
                    "No VS_FIXEDFILEINFO.")

                vs_fixedfileinfo = None

            vs = VersionInformation(vs_info, vs_fixedfileinfo)

            # Parse StringFileInfo and VarFileInfo entries.
            while p < offset + vs_info.wLength:

                fileinfo_offset = p

                try:

                    fileinfo = Structure(
                        self.__STRINGFILEINFO__,
                        'StringFileInfo',
                        data[p:p+36],
                        p)

                    if fileinfo.str_szKey != 'StringFileInfo':
                        raise ParseError(
                            "szKey does not match StringFileInfo.")

                except ParseError:

                    try:

                        # Try to re-parse as a VarFileInfo.
                        fileinfo = Structure(
                            self.__VARFILEINFO__,
                            'VarFileInfo',
                            data[p:p+30],
                            p)

                        if fileinfo.str_szKey != 'VarFileInfo':
                            raise ParseError(
                                "szKey does not match VarFileInfo.")

                    except ParseError:
                        outer.warnings.append(
                            "Unable to parse FileInfo.")

                        break

                if fileinfo.str_szKey == 'StringFileInfo':

                    # Padding to align on 32-bit relative boundary.
                    p += 36 + (base_rva + (p - offset) + 36) % 4

                    string_tables = list()

                    while p < fileinfo_offset + fileinfo.wLength:

                        string_table_offset = p

                        try:

                            string_table = Structure(
                                self.__STRINGTABLE__,
                                'StringTable',
                                data[p:p+24],
                                p)

                        except ParseError:
                            outer.warnings.append(
                                "Unable to parse StringTable.")

                            break

                        # Padding to align on 32-bit relative boundary.
                        p += 24 + (base_rva + (p - offset) + 24) % 4

                        strings = list()

                        while p < string_table_offset + string_table.wLength:

                            try:

                                string = Structure(
                                    self.__STRING__,
                                    'STRING',
                                    data[p:p+6],
                                    p)

                            except ParseError:
                                outer.warnings.append(
                                    "Unable to parse STRING.")

                                break

                            p += 6

                            # Retrieve the dynamic length szKey.
                            szKey = data.get_string_u(p, get_bytes=True)

                            if szKey is None:
                                outer.warnings.append(
                                    "Unable to parse STRING szKey.")

                                break

                            # Set the szKey as a field.
                            string.set_field('szKey', p, 6, szKey, 'U')

                            # Determine the length of the key.
                            klen = len(szKey) + 2

                            # Padding to align on 32-bit relative boundary.
                            pad = klen + (base_rva + (p - offset) + klen) % 4
                            p += pad

                            # Retrieve the Value.
                            if string.wValueLength > 0:
                                value = data.get_string_u(
                                    p, string.wValueLength-1, get_bytes=True)

                            else:
                                value = bytes()

                            if value is None:
                                outer.warnings.append(
                                    "Unable to parse STRING Value.")

                                break

                            # Set the Value as a field.
                            string.set_field('Value', p, 6+pad, value, 'U')

                            # To deal with zero length values.
                            if len(value) != 0:
                                vlen = len(value) + 2

                            else:
                                vlen = 0

                            # Padding to align on 32-bit relative boundary.
                            p += vlen +(base_rva + (p - offset) + vlen) % 4

                            strings.append(string)

                        string_tables.append(PE.ResourceContainer.StringTable({
                            'STRINGTABLE': string_table,
                            'strings': strings}))

                    vs.set_stringfileinfo(fileinfo, string_tables)

                elif fileinfo.str_szKey == 'VarFileInfo':

                    # Padding to align on 32-bit relative boundary.
                    p += 30 + (base_rva + (p - offset) + 30) % 4

                    vars_list = list()

                    while p < fileinfo_offset + fileinfo.wLength:

                        var_offset = p

                        try:

                            var = Structure(
                                self.__VAR__,
                                'Var',
                                data[p:p+30],
                                p)

                            if var.str_szKey != 'Translation':
                                raise ParseError(
                                    "szKey does not match Translation.")

                        except ParseError:
                            outer.warnings.append(
                                "Unable to parse VAR.")

                            break

                        # Padding to align on 32-bit relative boundary.
                        p += 30 + (base_rva + (p - offset) + 30) % 4

                        translations = list()

                        while p < var_offset + var.wLength:

                            w1 = int.from_bytes(
                                data[p:p+2], byteorder='little')

                            w2 = int.from_bytes(
                                data[p+2:p+4], byteorder='little')

                            translations.append((w1, w2))

                            # Padding to align on 32-bit boundary.
                            p += 4 + (base_rva + (p - offset) + 4) % 4

                        vars_list.append(PE.ResourceContainer.Var({
                            'VAR': var,
                            'translations': translations}))

                    vs.set_varfileinfo(fileinfo, vars_list)

            return vs


    class BaseRelocContainer():
        """ Container for relocation directory information.
        """

        Relocation = type('Relocation', (AttributeSetter,), {})
        """ class: Representation of relocations.
        """

        __IMAGE_BASE_RELOCATION__ = [
            ('VirtualAddress', 'd', 1),
            ('SizeOfBlock',    'd', 1)
        ]
        """ list of tuple: winnt.h definition of relocations.
        """

        __TARGET__ = [
            ('Value', 'w', 1)
        ]
        """ list of tuple: Definition of relocation target.
        """

        __RELOCATION_TYPE__ = {
            0:  'IMAGE_REL_BASED_ABSOLUTE',
            1:  'IMAGE_REL_BASED_HIGH',
            2:  'IMAGE_REL_BASED_LOW',
            3:  'IMAGE_REL_BASED_HIGHLOW',
            4:  'IMAGE_REL_BASED_HIGHADJ',
            5:  'IMAGE_REL_BASED_MIPS_JMPADDR',
            6:  'IMAGE_REL_BASED_SECTION',
            7:  'IMAGE_REL_BASED_REL',
            9:  'IMAGE_REL_BASED_MIPS_JMPADDR16',
            10: 'IMAGE_REL_BASED_DIR64',
            11: 'IMAGE_REL_BASED_HIGH3ADJ'
        }
        """ dict: relocation type mapping.
        """

        def __init__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:

            self.relocations = list()
            """ list of Relocation: stores relocation information.
            """

            self.__parse__(outer, data, directory)

        def __str__(self) -> str:

            builder = list()

            for relocation in self.relocations:
                builder.append(relocation.BASE_RELOCATION.__str__())

                builder.append('\n'.join(
                    map(lambda t: '%s %s' % (hex(t.Value), t.str_Type),
                        relocation.targets)))

            return '\n\n'.join(builder)

        def __parse__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:
            """ Parses relocation information.
            """

            # File offset of relocations.
            offset = outer.rva_to_file_offset(directory.VirtualAddress)

            p = offset

            counter = 0
            while p < offset + directory.Size:

                try:

                    relocation = Structure(
                        self.__IMAGE_BASE_RELOCATION__,
                        'IMAGE_BASE_RELOCATION',
                        data[p:p+8],
                        p)

                except ParseError:
                    outer.warnings.append(
                        "Unable to parse IMAGE_BASE_RELOCATION.")

                    break

                # Check if address is within the image.
                if relocation.VirtualAddress > \
                    outer.OPTIONAL_HEADER.SizeOfImage:
                    outer.warnings.append(
                        "VirtualAddress of relocation outside of image. "
                        "Stopped parsing the relocations directory.")

                    break

                # Check if SizeOfBlock is zero (results in looping).
                if relocation.SizeOfBlock == 0:
                    outer.warnings.append(
                        "SizeOfBlock of relocation is zero. "
                        "Stopped parsing the relocations directory.")

                    break

                targets = self._parse_relocation_targets(
                    outer,
                    data,
                    p+8,
                    relocation)

                self.relocations.append(PE.BaseRelocContainer.Relocation({
                    'BASE_RELOCATION': relocation,
                    'targets': targets}))

                p += relocation.SizeOfBlock

                counter += 1

                if counter == MAX_RELOCATIONS:
                    outer.warnings.append(
                        "Number of relocation entries is bigger than the "
                        "parser limit. Some relocations are not parsed.")

                    break

        def _parse_relocation_targets(
            self,
            outer,
            data: DataContainer,
            offset: int,
            relocation: Structure
        ) -> None:
            """ Parses the relocation targets.
            """

            p = offset

            number_of_targets = min(
                data.length_until_eof(p) // 2,
                (relocation.SizeOfBlock - 8) // 2,
                MAX_RELOC_TARGETS)

            if number_of_targets == MAX_RELOC_TARGETS:
                outer.warnings.append(
                    "Number of relocation targets is bigger than the  "
                    "parser limit. Some targets are not parsed.")

            elif number_of_targets == data.length_until_eof(p) // 2:
                outer.warnings.append(
                    "Relocation targets extend beyond eof.")

            targets = list()

            for idx in range(0, number_of_targets):

                try:

                    target = Structure(
                        self.__TARGET__,
                        'Target',
                        data[p+(idx*2):p+(idx*2)+2],
                        p+(idx*2))

                except ParseError:
                    outer.warnings.append(
                        "Unable to parse relocation Target.")

                    break

                try:

                    # Set the target type.
                    target.set_other(
                        'str_Type',
                        self.__RELOCATION_TYPE__[target.Value >> 12])

                except IndexError:
                    outer.warnings.append(
                        "Unknown Target type.")

                    target.set_other('str_Type', None)

                # Set the target offset.
                target.set_other('int_Offset', target.Value & 0x0FFF)

                targets.append(target)

            return targets


    class DebugContainer():
        """ Container for debug directory information.
        """

        Entry = type('Entry', (AttributeSetter,), {})
        """ class: Representation of debug entry.
        """

        __IMAGE_DEBUG_DIRECTORY__ = [
            ('Characteristics',  'd', 1),
            ('TimeDateStamp',    't', 1),
            ('MajorVersion',     'w', 1),
            ('MinorVersion',     'w', 1),
            ('Type',             'd', 1),
            ('SizeOfData',       'd', 1),
            ('AddressOfRawData', 'd', 1),
            ('PointerToRawData', 'd', 1)
        ]
        """ list of tuple: winnt.h definition of debug directory.
        """

        __DEBUG_TYPE__ = {
            0:  'DEBUG_TYPE_UNKNOWN',
            1:  'DEBUG_TYPE_COFF',
            2:  'DEBUG_TYPE_CODEVIEW',
            3:  'DEBUG_TYPE_FPO',
            4:  'DEBUG_TYPE_MISC',
            5:  'DEBUG_TYPE_EXCEPTION',
            6:  'DEBUG_TYPE_FIXUP',
            7:  'DEBUG_TYPE_OMAP_TO_SRC',
            8:  'DEBUG_TYPE_OMAP_FROM_SRC',
            9:  'DEBUG_TYPE_BORLAND',
            10: 'DEBUG_TYPE_RESERVED10',
            11: 'DEBUG_TYPE_CLSID',
            12: 'IMAGE_DEBUG_TYPE_VC_FEATURE',
            13: 'IMAGE_DEBUG_TYPE_POGO',
            14: 'IMAGE_DEBUG_TYPE_ILTCG',
            15: 'IMAGE_DEBUG_TYPE_MPX',
            16: 'DEBUG_TYPE_REPRO',
            20: 'DEBUG_TYPE_EX_DLLCHARACTERISTICS'
        }
        """ dict: Debug type mapping.
        """

        __IMAGE_CV_HEADER__ = [
            ('Signature', 'A',  4),
            ('Offset',    'd',  1)
        ]
        """ list of tuple: winnt.h definition of CodeView header.
        """

        __IMAGE_CV_INFO_PDB20__ = [
            ('CvHeaderSignature', 'A', 4),
            ('CvHeaderOffset',    'd', 1),
            ('Signature',         't', 1),
            ('Age',               'd', 1)
        ]
        """ list of tuple: winnt.h definition of PDB20.
        """

        __IMAGE_CV_INFO_PDB70__ = [
            ('CvSignature', 'A', 4),
            ('Signature',   'g', 1),
            ('Age',         'd', 1)
        ]
        """ list of tuple: winnt.h definition of PDB70.
        """

        __IMAGE_DEBUG_MISC__ = [
            ('DataType',  'd', 1),
            ('Length',    'd', 1),
            ('Unicode',   'b', 1),
            ('Reserved',  'b', 3)
        ]
        """ list of tuple: winnt.h definition MISC.
        """

        __IMAGE_POGO_SIGNATURE__ = [
            ('Signature', 'A', 4)
        ]
        """ list of tuple: winnt.h definition of POGO.
        """

        def __init__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:

            self.entries = list()
            """ list of Entry: Stores debug entries.
            """

            self.__parse__(outer, data, directory)

        def __str__(self) -> str:
            return '\n\n'.join(
                map(lambda e: '%s\n\n%s' % (
                    e.DEBUG_DIRECTORY.__str__(),
                    e.ENTRY.__str__()), self.entries))

        def __parse__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:
            """ Parses debug information.
            """

            p = outer.rva_to_file_offset(directory.VirtualAddress)

            # Set a maximum number of debug directories.
            number_of_directories = min(
                data.length_until_eof(p) // 28,
                directory.Size // 28,
                MAX_DEBUG)

            if number_of_directories == MAX_DEBUG:
                outer.warnings.append(
                    "Number of debug directories is bigger than the "
                    "parser limit. Some directories are not parsed.")

            elif number_of_directories == data.length_until_eof(p) // 28:
                outer.warnings.append(
                    "DEBUG_DIRECTORY array extends beyond eof.")

            for _ in range(number_of_directories):

                try:

                    directory = Structure(
                        self.__IMAGE_DEBUG_DIRECTORY__,
                        'IMAGE_DEBUG_DIRECTORY',
                        data[p:p+28],
                        p)

                except ParseError:
                    outer.warnings.append(
                        "Unable to parse IMAGE_DEBUG_DIRECTORY.")

                    break

                try:

                    # Add the type to the directory.
                    directory.set_other(
                        'str_Type', self.__DEBUG_TYPE__[directory.Type])

                except KeyError:
                    directory.set_other('str_Type', None)

                # Debug type DEBUG_TYPE_CODEVIEW (pdb).
                if directory.Type == 2:
                    entry = self._debug_codeview(outer, data, directory)

                # Debug type DEBUG_TYPE_MISC (dbg).
                elif directory.Type == 4:
                    entry = self._debug_misc(outer, data, directory)

                # Debug type DEBUG_TYPE_POGO (sig).
                elif directory.Type == 13:
                    entry = self._debug_pogo(outer, data, directory)

                else:
                    entry = None

                    try:
                        outer.warnings.append(
                            "Parsing %s is not yet implemented." %
                            self.__DEBUG_TYPE__[directory.Type])

                    except KeyError:
                        outer.warnings.append(
                            "Unknown debug directory type.")

                self.entries.append(PE.DebugContainer.Entry({
                    'DEBUG_DIRECTORY': directory,
                    'ENTRY': entry}))

                p += 28

        def _debug_codeview(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> Structure:
            """ Returns CodeView debug information.
            """

            p = directory.PointerToRawData

            try:

                cv = Structure(
                    self.__IMAGE_CV_HEADER__,
                    'IMAGE_CV_HEADER',
                    data[p:p+8],
                    p)

            except ParseError:
                outer.warnings.append(
                    "Unable to parse IMAGE_CV_HEADER.")

                return None

            # PDB 7.0 files (RSDS).
            if cv.Signature == b'RSDS':
                header_type = self.__IMAGE_CV_INFO_PDB70__
                header_name = 'IMAGE_CV_INFO_PDB70'
                size = 24

            # PDB 2.0 files (NB10).
            elif cv.Signature == b'NB10':
                header_type = self.__IMAGE_CV_INFO_PDB20__
                header_name = 'IMAGE_CV_INFO_PDB20'
                size = 16

            else:

                outer.warnings.append(
                    "Parsing CodeView signature %s is not implemented." %
                    cv.Signature)

                return cv

            try:

                pdb = Structure(
                    header_type,
                    header_name,
                    data[p:p+size],
                    p)

            except ParseError:
                outer.warnings.append(
                    "Unable to parse CodeView entry.")

            # Parse the PDB file name.
            name = data.get_string_a(
                directory.PointerToRawData + size,
                get_bytes=True)

            # Check if parsing was successful.
            if name is None:
                outer.warnings.append(
                    "Unable to parse PDB file name.")

            # Add the name as a field of the structure.
            pdb.set_field(
                'PdbFileName',
                directory.PointerToRawData + size,
                size,
                name,
                'A')

            return pdb

        def _debug_pogo(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> Structure:
            """ Returns POGO debug information.
            """

            p = directory.PointerToRawData

            try:

                signature = Structure(
                    self.__IMAGE_POGO_SIGNATURE__,
                    'IMAGE_POGO_SIGNATURE',
                    data[p:p+4],
                    p)

            except ParseError:
                outer.warnings.append(
                    "Unable to parse IMAGE_POGO_SIGNATURE.")

                return None

            return signature

        def _debug_misc(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> Structure:
            """ Returns MISC debug information.
            """

            p = directory.PointerToRawData

            try:

                dbg = Structure(
                    self.__IMAGE_DEBUG_MISC__,
                    'IMAGE_DEBUG_MISC',
                    data[p:p+12],
                    p)

            except ParseError:
                outer.warnings.append(
                    "Unable to parse IMAGE_DEBUG_MISC.")

                return None

            # Parse the DBG file name.
            if dbg.Unicode:

                name = data.get_string_u(
                    directory.PointerToRawData + 12,
                    get_bytes=True)

            else:

                name = data.get_string_a(
                    directory.PointerToRawData + 12,
                    get_bytes=True)

            # Check if parsing was successful.
            if name is None:
                outer.warnings.append(
                    "Unable to parse DBG name.")

            # Add the name as a field of the structure.
            dbg.set_field(
                'Data',
                directory.PointerToRawData + 12,
                12,
                name,
                'A')

            return dbg


    class TlsContainer():
        """ Container for thread local storage directory information.
        """

        __IMAGE_TLS_DIRECTORY__ = [
            ('StartAddressOfRawData', 'd', 1),
            ('EndAddressOfRawData',   'd', 1),
            ('AddressOfIndex',        'd', 1),
            ('AddressOfCallBacks',    'd', 1),
            ('SizeOfZeroFill',        'd', 1),
            ('Characteristics',       'd', 1)
        ]
        """ list tuple: winnt.h definition of 32 bit tls directory.
        """

        __IMAGE_TLS_DIRECTORY64__ = [
            ('StartAddressOfRawData', 'u', 1),
            ('EndAddressOfRawData',   'u', 1),
            ('AddressOfIndex',        'u', 1),
            ('AddressOfCallBacks',    'u', 1),
            ('SizeOfZeroFill',        'd', 1),
            ('Characteristics',       'd', 1)
        ]
        """ list tuple: winnt.h definition of 64 bit tls directory.
        """

        def __init__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:

            self.TLS_DIRECTORY = None
            """ Structure: Stores the tls directory structure.
            """

            self.__parse__(outer, data, directory)

        def __str__(self) -> str:
            return self.TLS_DIRECTORY.__str__()

        def __parse__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:
            """ Parses thread local storage information.
            """

            p = outer.rva_to_file_offset(directory.VirtualAddress)

            if outer.pe_type == NT_OPTIONAL_HDR32_MAGIC:
                header_type = self.__IMAGE_TLS_DIRECTORY__
                header_name = 'TLS_DIRECTORY'
                size = 24

            elif outer.pe_type == NT_OPTIONAL_HDR64_MAGIC:
                header_type = self.__IMAGE_TLS_DIRECTORY64__
                header_name = 'TLS_DIRECTORY64'
                size = 40

            else:
                outer.warnings.append(
                    "Unknown PE type. Can't parse tls directory.")

                return None

            try:

                self.TLS_DIRECTORY = Structure(
                    header_type,
                    header_name,
                    data[p:p+size],
                    p)

            except ParseError:
                outer.warnings.append(
                    "Unable to parse TLS_DIRECTORY.")

                return None


    class LoadConfigContainer():
        """ Container for load configuration directory information.
        """

        __IMAGE_LOAD_CONFIG_DIRECTORY__ = [
            ('Characteristics',                'd', 1),
            ('TimeDateStamp',                  't', 1),
            ('MajorVersion',                   'w', 1),
            ('MinorVersion',                   'w', 1),
            ('GlobalFlagsClear',               'd', 1),
            ('GlobalFlagsSet',                 'd', 1),
            ('CriticalSectionDefaultTimeout',  'd', 1),
            ('DeCommitFreeBlockThreshold',     'd', 1),
            ('DeCommitTotalFreeThreshold',     'd', 1),
            ('LockPrefixTable',                'd', 1),
            ('MaximumAllocationSize',          'd', 1),
            ('VirtualMemoryThreshold',         'd', 1),
            ('ProcessHeapFlags',               'd', 1),
            ('ProcessAffinityMask',            'd', 1),
            ('CSDVersion',                     'w', 1),
            ('Reserved1',                      'w', 1),
            ('EditList',                       'd', 1),
            ('SecurityCookie',                 'd', 1),
            ('SEHandlerTable',                 'd', 1),
            ('SEHandlerCount',                 'd', 1),
            ('GuardCFCheckFunctionPointer',    'd', 1),
            ('GuardCFDispatchFunctionPointer', 'd', 1),
            ('GuardCFFunctionTable',           'd', 1),
            ('GuardCFFunctionCount',           'd', 1),
            ('GuardFlags',                     'd', 1),
            ('CodeIntegrity',                  'z', 1),
            ('GuardAddressTakenIatEntryTable', 'd', 1),
            ('GuardAddressTakenIatEntryCount', 'd', 1),
            ('GuardLongJumpTargetTable',       'd', 1),
            ('GuardLongJumpTargetCount',       'd', 1)
        ]
        """ list of tuple: winnt.h definition of 32 bit load config.

            Corkami:
                -> HeapFlags & AffinityMask flipped w.r.t. MSDN docs.
        """

        __IMAGE_LOAD_CONFIG_DIRECTORY64__ = [
            ('Characteristics',                'd', 1),
            ('TimeDateStamp',                  't', 1),
            ('MajorVersion',                   'w', 1),
            ('MinorVersion',                   'w', 1),
            ('GlobalFlagsClear',               'd', 1),
            ('GlobalFlagsSet',                 'd', 1),
            ('CriticalSectionDefaultTimeout',  'd', 1),
            ('DeCommitFreeBlockThreshold',     'u', 1),
            ('DeCommitTotalFreeThreshold',     'u', 1),
            ('LockPrefixTable',                'u', 1),
            ('MaximumAllocationSize',          'u', 1),
            ('VirtualMemoryThreshold',         'u', 1),
            ('ProcessAffinityMask',            'u', 1),
            ('ProcessHeapFlags',               'd', 1),
            ('CSDVersion',                     'w', 1),
            ('Reserved1',                      'w', 1),
            ('EditList',                       'u', 1),
            ('SecurityCookie',                 'u', 1),
            ('SEHandlerTable',                 'u', 1),
            ('SEHandlerCount',                 'u', 1),
            ('GuardCFCheckFunctionPointer',    'u', 1),
            ('GuardCFDispatchFunctionPointer', 'u', 1),
            ('GuardCFFunctionTable',           'u', 1),
            ('GuardCFFunctionCount',           'u', 1),
            ('GuardFlags',                     'd', 1),
            ('CodeIntegrity',                  'z', 1),
            ('GuardAddressTakenIatEntryTable', 'u', 1),
            ('GuardAddressTakenIatEntryCount', 'u', 1),
            ('GuardLongJumpTargetTable',       'u', 1),
            ('GuardLongJumpTargetCount',       'u', 1)
        ]
        """ list of tuple: winnt.h definition of 64 bit load config.
        """

        __GUARDFLAGS__ = [
            ('IMAGE_GUARD_CF_INSTRUMENTED',                    0x00000100),
            ('IMAGE_GUARD_CFW_INSTRUMENTED',                   0x00000200),
            ('IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT',          0x00000400),
            ('IMAGE_GUARD_SECURITY_COOKIE_UNUSED',             0x00000800),
            ('IMAGE_GUARD_PROTECT_DELAYLOAD_IAT',              0x00001000),
            ('IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION',   0x00002000),
            ('IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT', 0x00004000),
            ('IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION',       0x00008000),
            ('IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT',          0x00010000),
            ('IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK',        0xF0000000)
        ]
        """ list of tuple: Guard flag definitions.
        """

        def __init__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:

            self.LOAD_CONFIG_DIRECTORY = None
            """ Structure: Stores the load configuration directory.
            """

            self.__parse__(outer, data, directory)

        def __str__(self) -> str:
            return self.LOAD_CONFIG_DIRECTORY.__str__()

        def __parse__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:
            """ Parses thread load configuration information.
            """

            p = outer.rva_to_file_offset(directory.VirtualAddress)

            if outer.pe_type == NT_OPTIONAL_HDR32_MAGIC:
                header_type = self.__IMAGE_LOAD_CONFIG_DIRECTORY__
                header_name = 'LOAD_CONFIG_DIRECTORY'
                size = 120

            elif outer.pe_type == NT_OPTIONAL_HDR64_MAGIC:
                header_type = self.__IMAGE_LOAD_CONFIG_DIRECTORY64__
                header_name = 'LOAD_CONFIG_DIRECTORY64'
                size = 192

            else:
                outer.warnings.append(
                    "Unkown PE type. Can't parse load configuration.")

                return None

            try:

                self.LOAD_CONFIG_DIRECTORY = Structure(
                    header_type,
                    header_name,
                    data[p:p+size],
                    p)

            except ParseError:
                outer.warnings.append(
                    "Unable to parse LOAD_CONFIG_DIRECTORY.")

                return None

            self.LOAD_CONFIG_DIRECTORY.set_flags(
                self.LOAD_CONFIG_DIRECTORY.GuardFlags,
                self.__GUARDFLAGS__)


    class BoundImportContainer():
        """ Container for bound import directory information.
        """

        __IMAGE_BOUND_IMPORT_DESCRIPTOR__ = [
            ('TimeDateStamp',               't', 1),
            ('OffsetModuleName',            'w', 1),
            ('NumberOfModuleForwarderRefs', 'w', 1)
        ]
        """ list of tuple: winnt.h definition of bound import descriptor.
        """

        __IMAGE_BOUND_FORWARDER_REF__ = [
            ('TimeDateStamp',    't', 1),
            ('OffsetModuleName', 'w', 1),
            ('Reserved',         'w', 1)
        ]
        """ list of tuple: winnt.h definition of bound forwarder references.
        """

        def __init__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:

            self.descriptors = list()
            """ list of Structure: BOUND_IMPORT_DESCRIPTOR structures.
            """

            self.__parse__(outer, data, directory)

        def __str__(self) -> str:
            return '\n\n'.join(
                map(lambda d: d.__str__(),
                    self.descriptors))

        def __parse__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:
            """ Parses bound import information.
            """

            # Keeps count of the number of module forwarder refs. If a
            # bound import is bound to a module that forwards to other
            # modules, forwarded-to modules TD stamps are checked too.
            count = 0

            p = outer.rva_to_file_offset(directory.VirtualAddress)

            # Set a maximum number of bound import descriptors.
            number_of_bound_descriptors = min(
                data.length_until_eof(p) // 8,
                MAX_DLLS)

            maximum_failures = 5
            for _ in range(number_of_bound_descriptors):

                if count <= 0:

                    try:
                        entry = Structure(
                            self.__IMAGE_BOUND_IMPORT_DESCRIPTOR__,
                            'IMAGE_BOUND_IMPORT_DESCRIPTOR',
                            data[p:p+8],
                            p)

                    except ParseError:
                        outer.warnings.append(
                            "Unable to parse IMAGE_BOUND_IMPORT_DESCRIPTOR.")

                        break

                    # Check whether the next entries are forwarder refs.
                    count = entry.NumberOfModuleForwarderRefs

                else:

                    # Parse the next forwarder reference.

                    try:

                        entry = Structure(
                            self.__IMAGE_BOUND_FORWARDER_REF__,
                            'IMAGE_BOUND_FORWARDER_REF',
                            data[p:p+8],
                            p)

                    except ParseError:
                        outer.warnings.append(
                            "Unable to parse IMAGE_BOUND_FORWARDER_REF.")

                        break

                    count -= 1

                # Check for null terminating descriptor.
                if entry.all_zeros():
                    break

                # Get the entry name.
                entry_name = data.get_string_a(
                    outer.rva_to_file_offset(
                        directory.VirtualAddress + entry.OffsetModuleName))

                # Check if parsing was successful.
                if entry_name is None:
                    outer.warnings.append(
                        "Unable to parse bound import name.")

                    maximum_failures -= 1
                    if maximum_failures < 0:
                        break

                entry.set_other('str_Name', entry_name)

                # Append the entry descriptor.
                self.descriptors.append(entry)

                p += 8

            else:
                outer.warnings.append(
                    "Anomalous number of IMAGE_BOUND_IMPORT_DESCRIPTOR. "
                    "Some descriptors are not parsed.")

            if maximum_failures < 0:
                outer.warnings.append(
                    "Hit maximum number of failures whilst parsing bound imports.")


    class DelayImportContainer(ImportBaseClass):
        """ Container for delay load import directory information.
        """

        __IMAGE_DELAY_IMPORT_DESCRIPTOR__ = [
            ('grAttrs',     'd', 1),
            ('szName',      'd', 1),
            ('phmod',       'd', 1),
            ('pIAT',        'd', 1),
            ('pINT',        'd', 1),
            ('pBoundIAT',   'd', 1),
            ('pUnloadIAT',  'd', 1),
            ('dwTimeStamp', 't', 1)
        ]
        """ list of tuple: winnt.h definition of delay import descriptor.
        """

        def __init__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:

            super().__init__()

            self.__parse__(outer, data, directory)

        def __str__(self) -> str:
            return '\n\n'.join(
                map(lambda d: d.__str__(), self.dlls))

        def __parse__(
            self,
            outer,
            data: DataContainer,
            directory: Structure
        ) -> None:
            """ Parses delay load import information.
            """

            p = outer.rva_to_file_offset(directory.VirtualAddress)

            # Set a maximum number of import descriptors.
            number_of_descriptors = min(
                data.length_until_eof(p) // 32,
                MAX_DLLS)

            maximum_failures = 5
            for _ in range(number_of_descriptors):

                try:

                    descriptor = Structure(
                        self.__IMAGE_DELAY_IMPORT_DESCRIPTOR__,
                        'IMAGE_DELAY_IMPORT_DESCRIPTOR',
                        data[p:p+32],
                        p)

                except ParseError:
                    outer.warnings.append(
                        "Unable to parse IMAGE_DELAY_IMPORT_DESCRIPTOR.")

                    break

                # Check for null terminating descriptor.
                if descriptor.all_zeros():
                    break

                # Parse the delay import address table.
                addresses = self.parse_table(
                    outer, data, descriptor.pIAT)

                self.address_table.append(addresses)

                # Parse the delay import name table.
                names = self.parse_table(
                    outer, data, descriptor.pINT)

                self.name_table.append(names)

                # Get the dll name.
                dll_name = data.get_string_a(
                    outer.rva_to_file_offset(
                        descriptor.szName))

                # Check if parsing was successful.
                if dll_name is None:
                    outer.warnings.append(
                        "Unable to parse DLL name.")

                    maximum_failures -= 1
                    if maximum_failures < 0:
                        break

                descriptor.set_other('str_Name', dll_name)

                # Construct the dll.
                dll = self.create_dll(
                    outer,
                    data,
                    descriptor,
                    dll_name,
                    bool(descriptor.dwTimeStamp),
                    addresses,
                    names)

                # Append the dll.
                self.dlls.append(dll)

                p += 32

            else:
                outer.warnings.append(
                    "Anomalous number of IMAGE_DELAY_IMPORT_DESCRIPTOR. "
                    "Some delay DLLs are not parsed.")

            if maximum_failures < 0:
                outer.warnings.append(
                    "Hit maximum number of failures parsing delay imports.")


    __IMAGE_DOS_HEADER__ = [
        ('e_magic',    'w', 1),
        ('e_cblp',     'w', 1),
        ('e_cp',       'w', 1),
        ('e_crlc',     'w', 1),
        ('e_cparhdr',  'w', 1),
        ('e_minalloc', 'w', 1),
        ('e_maxalloc', 'w', 1),
        ('e_ss',       'w', 1),
        ('e_sp',       'w', 1),
        ('e_csum',     'w', 1),
        ('e_ip',       'w', 1),
        ('e_cs',       'w', 1),
        ('e_lfarlc',   'w', 1),
        ('e_ovno',     'w', 1),
        ('e_res',      'w', 4),
        ('e_oemid',    'w', 1),
        ('e_oeminfo',  'w', 1),
        ('e_res2',     'w', 10),
        ('e_lfanew',   'd', 1)
    ]
    """ list of tuple: winnt.h definition of the DOS header.
    """

    __IMAGE_NT_HEADERS__ = [
        ('Signature', 'd', 1)
    ]
    """ list of tuple: winnt.h definition of the NT headers.
    """

    __IMAGE_FILE_HEADER__ = [
        ('Machine',              'w', 1),
        ('NumberOfSections',     'w', 1),
        ('TimeDateStamp',        't', 1),
        ('PointerToSymbolTable', 'd', 1),
        ('NumberOfSymbols',      'd', 1),
        ('SizeOfOptionalHeader', 'w', 1),
        ('Characteristics',      'w', 1)
    ]
    """ list of tuple: winnt.h definition of the file header.
    """

    __MACHINE__ = {
        0x014c: 'Intel 386 or later',
        0x8664: 'AMD64'
    }
    """ dict: Machine type mapping.
    """

    __FILE_CHARACTERISTICS__ = [
        ('IMAGE_FILE_RELOCS_STRIPPED',         0x0001),
        ('IMAGE_FILE_EXECUTABLE_IMAGE',        0x0002),
        ('IMAGE_FILE_LINE_NUMS_STRIPPED',      0x0004),
        ('IMAGE_FILE_LOCAL_SYMS_STRIPPED',     0x0008),
        ('IMAGE_FILE_AGGRESSIVE_WS_TRIM',      0x0010),
        ('IMAGE_FILE_LARGE_ADDRESS_AWARE',     0x0020),
        ('IMAGE_FILE_16BIT_MACHINE',           0x0040),
        ('IMAGE_FILE_BYTES_REVERSED_LO',       0x0080),
        ('IMAGE_FILE_32BIT_MACHINE',           0x0100),
        ('IMAGE_FILE_DEBUG_STRIPPED',          0x0200),
        ('IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP', 0x0400),
        ('IMAGE_FILE_NET_RUN_FROM_SWAP',       0x0800),
        ('IMAGE_FILE_SYSTEM',                  0x1000),
        ('IMAGE_FILE_DLL',                     0x2000),
        ('IMAGE_FILE_UP_SYSTEM_ONLY',          0x4000),
        ('IMAGE_FILE_BYTES_REVERSED_HI',       0x8000)
    ]
    """ list of tuple: winnt.h definition of file characteristics.
    """

    __IMAGE_OPTIONAL_HEADER__ = [
        ('Magic',                       'w', 1),
        ('MajorLinkerVersion',          'b', 1),
        ('MinorLinkerVersion',          'b', 1),
        ('SizeOfCode',                  'd', 1),
        ('SizeOfInitializedData',       'd', 1),
        ('SizeOfUninitializedData',     'd', 1),
        ('AddressOfEntryPoint',         'd', 1),
        ('BaseOfCode',                  'd', 1),
        ('BaseOfData',                  'd', 1),
        ('ImageBase',                   'd', 1),
        ('SectionAlignment',            'd', 1),
        ('FileAlignment',               'd', 1),
        ('MajorOperatingSystemVersion', 'w', 1),
        ('MinorOperatingSystemVersion', 'w', 1),
        ('MajorImageVersion',           'w', 1),
        ('MinorImageVersion',           'w', 1),
        ('MajorSubsystemVersion',       'w', 1),
        ('MinorSubsystemVersion',       'w', 1),
        ('Win32VersionValue',           'd', 1),
        ('SizeOfImage',                 'd', 1),
        ('SizeOfHeaders',               'd', 1),
        ('CheckSum',                    'd', 1),
        ('Subsystem',                   'w', 1),
        ('DllCharacteristics',          'w', 1),
        ('SizeOfStackReserve',          'd', 1),
        ('SizeOfStackCommit',           'd', 1),
        ('SizeOfHeapReserve',           'd', 1),
        ('SizeOfHeapCommit',            'd', 1),
        ('LoaderFlags',                 'd', 1),
        ('NumberOfRvaAndSizes',         'd', 1)
    ]
    """ list of tuple: winnt.h definition of 32 bit optional header.
    """

    __IMAGE_OPTIONAL_HEADER64__ = [
        ('Magic',                       'w', 1),
        ('MajorLinkerVersion',          'b', 1),
        ('MinorLinkerVersion',          'b', 1),
        ('SizeOfCode',                  'd', 1),
        ('SizeOfInitializedData',       'd', 1),
        ('SizeOfUninitializedData',     'd', 1),
        ('AddressOfEntryPoint',         'd', 1),
        ('BaseOfCode',                  'd', 1),
        ('ImageBase',                   'u', 1),
        ('SectionAlignment',            'd', 1),
        ('FileAlignment',               'd', 1),
        ('MajorOperatingSystemVersion', 'w', 1),
        ('MinorOperatingSystemVersion', 'w', 1),
        ('MajorImageVersion',           'w', 1),
        ('MinorImageVersion',           'w', 1),
        ('MajorSubsystemVersion',       'w', 1),
        ('MinorSubsystemVersion',       'w', 1),
        ('Win32VersionValue',           'd', 1),
        ('SizeOfImage',                 'd', 1),
        ('SizeOfHeaders',               'd', 1),
        ('CheckSum',                    'd', 1),
        ('Subsystem',                   'w', 1),
        ('DllCharacteristics',          'w', 1),
        ('SizeOfStackReserve',          'u', 1),
        ('SizeOfStackCommit',           'u', 1),
        ('SizeOfHeapReserve',           'u', 1),
        ('SizeOfHeapCommit',            'u', 1),
        ('LoaderFlags',                 'd', 1),
        ('NumberOfRvaAndSizes',         'd', 1)
    ]
    """ list of tuple: winnt.h definition of 64 bit optional header.
    """

    __DllCHARACTERISTICS__ = [
        ('IMAGE_LIBRARY_PROCESS_INIT',                     0x0001),
        ('IMAGE_LIBRARY_PROCESS_TERM',                     0x0002),
        ('IMAGE_LIBRARY_THREAD_INIT',                      0x0004),
        ('IMAGE_LIBRARY_THREAD_TERM',                      0x0008),
        ('IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA',       0x0020),
        ('IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE',          0x0040),
        ('IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY',       0x0080),
        ('IMAGE_DLLCHARACTERISTICS_NX_COMPAT',             0x0100),
        ('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION',          0x0200),
        ('IMAGE_DLLCHARACTERISTICS_NO_SEH',                0x0400),
        ('IMAGE_DLLCHARACTERISTICS_NO_BIND',               0x0800),
        ('IMAGE_DLLCHARACTERISTICS_APPCONTAINER',          0x1000),
        ('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER',            0x2000),
        ('IMAGE_DLLCHARACTERISTICS_GUARD_CF',              0x4000),
        ('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', 0x8000)
    ]
    """ list of tuple: winnt.h definition of DLL characteristics.
    """

    __IMAGE_SECTION_HEADER__ = [
        ('Name',                        'A', 8),
        ('PhysicalAddress/VirtualSize', 'd', 1),
        ('VirtualAddress',              'd', 1),
        ('SizeOfRawData',               'd', 1),
        ('PointerToRawData',            'd', 1),
        ('PointerToRelocations',        'd', 1),
        ('PointerToLinenumbers',        'd', 1),
        ('NumberOfRelocations',         'w', 1),
        ('NumberOfLinenumbers',         'w', 1),
        ('Characteristics',             'd', 1)
    ]
    """ list of tuple: winnt.h definition of section header.
    """

    __SCN_CHARACTERISTICS__ = [
        ('IMAGE_SCN_TYPE_REG',               0x00000000),
        ('IMAGE_SCN_TYPE_DSECT',             0x00000001),
        ('IMAGE_SCN_TYPE_NOLOAD',            0x00000002),
        ('IMAGE_SCN_TYPE_GROUP',             0x00000004),
        ('IMAGE_SCN_TYPE_NO_PAD',            0x00000008),
        ('IMAGE_SCN_TYPE_COPY',              0x00000010),

        ('IMAGE_SCN_CNT_CODE',               0x00000020),
        ('IMAGE_SCN_CNT_INITIALIZED_DATA',   0x00000040),
        ('IMAGE_SCN_CNT_UNINITIALIZED_DATA', 0x00000080),

        ('IMAGE_SCN_LNK_OTHER',              0x00000100),
        ('IMAGE_SCN_LNK_INFO',               0x00000200),
        ('IMAGE_SCN_LNK_OVER',               0x00000400),
        ('IMAGE_SCN_LNK_REMOVE',             0x00000800),
        ('IMAGE_SCN_LNK_COMDAT',             0x00001000),

        ('IMAGE_SCN_MEM_PROTECTED',          0x00004000),
        ('IMAGE_SCN_NO_DEFER_SPEC_EXC',      0x00004000),
        ('IMAGE_SCN_GPREL',                  0x00008000),
        ('IMAGE_SCN_MEM_FARDATA',            0x00008000),
        ('IMAGE_SCN_MEM_SYSHEAP',            0x00010000),
        ('IMAGE_SCN_MEM_PURGEABLE',          0x00020000),
        ('IMAGE_SCN_MEM_16BIT',              0x00020000),
        ('IMAGE_SCN_MEM_LOCKED',             0x00040000),
        ('IMAGE_SCN_MEM_PRELOAD',            0x00080000),

        ('IMAGE_SCN_ALIGN_1BYTES',           0x00100000),
        ('IMAGE_SCN_ALIGN_2BYTES',           0x00200000),
        ('IMAGE_SCN_ALIGN_4BYTES',           0x00300000),
        ('IMAGE_SCN_ALIGN_8BYTES',           0x00400000),
        ('IMAGE_SCN_ALIGN_16BYTES',          0x00500000),
        ('IMAGE_SCN_ALIGN_32BYTES',          0x00600000),
        ('IMAGE_SCN_ALIGN_64BYTES',          0x00700000),
        ('IMAGE_SCN_ALIGN_128BYTES',         0x00800000),
        ('IMAGE_SCN_ALIGN_256BYTES',         0x00900000),
        ('IMAGE_SCN_ALIGN_512BYTES',         0x00A00000),
        ('IMAGE_SCN_ALIGN_1024BYTES',        0x00B00000),
        ('IMAGE_SCN_ALIGN_2048BYTES',        0x00C00000),
        ('IMAGE_SCN_ALIGN_4096BYTES',        0x00D00000),
        ('IMAGE_SCN_ALIGN_8192BYTES',        0x00E00000),
        ('IMAGE_SCN_ALIGN_MASK',             0x00F00000),

        ('IMAGE_SCN_LNK_NRELOC_OVFL',        0x01000000),
        ('IMAGE_SCN_MEM_DISCARDABLE',        0x02000000),
        ('IMAGE_SCN_MEM_NOT_CACHED',         0x04000000),
        ('IMAGE_SCN_MEM_NOT_PAGED',          0x08000000),
        ('IMAGE_SCN_MEM_SHARED',             0x10000000),
        ('IMAGE_SCN_MEM_EXECUTE',            0x20000000),
        ('IMAGE_SCN_MEM_READ',               0x40000000),
        ('IMAGE_SCN_MEM_WRITE',              0x80000000)
    ]
    """ list of tuple: winnt.h definition of section characteristics.
    """

    __IMAGE_DATA_DIRECTORY__ = [
        ('VirtualAddress', 'd', 1),
        ('Size',           'd', 1)
    ]
    """ list of tuple: winnt.h definition of data directory.
    """

    __DIRECTORY_ENTRIES__ = [
        'IMAGE_DIRECTORY_ENTRY_EXPORT',
        'IMAGE_DIRECTORY_ENTRY_IMPORT',
        'IMAGE_DIRECTORY_ENTRY_RESOURCE',
        'IMAGE_DIRECTORY_ENTRY_EXCEPTION',
        'IMAGE_DIRECTORY_ENTRY_SECURITY',
        'IMAGE_DIRECTORY_ENTRY_BASERELOC',
        'IMAGE_DIRECTORY_ENTRY_DEBUG',
        'IMAGE_DIRECTORY_ENTRY_COPYRIGHT',
        'IMAGE_DIRECTORY_ENTRY_GLOBALPTR',
        'IMAGE_DIRECTORY_ENTRY_TLS',
        'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG',
        'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',
        'IMAGE_DIRECTORY_ENTRY_IAT',
        'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',
        'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR',
        'RESERVED'
    ]
    """ list: winnt.h definition of directory entries.
    """

    def __init__(
        self,
        fname: str = None,
        fast_load: bool = False,
        is_entropy: bool = True
    ) -> None:

        self.fname = fname
        """ str: The filename of the PE file.
        """

        self.data = None
        """ DataContainer: Contains the PE file bytes.
        """

        self.fast_load = fast_load
        """ bool: True if data directories aren't parsed.
        """

        self.warnings = list()
        """ list of str: Stores warnings.
        """

        self.pe_size = 0
        """ int: Number of bytes in the file.
        """

        self.pe_type = 0
        """ int: PE type defined by optional header.
        """

        self.hashes = dict()
        """ dict: Contains file hashes.
        """

        self.is_entropy = is_entropy
        """ bool: True to perform entropy calculations.
        """

        self.DOS_HEADER = None
        """ Structure: DOS header.
        """

        self.NT_HEADERS = None
        """ Structure: NT headers.
        """

        self.FILE_HEADER = None
        """ Structure: File header.
        """

        self.OPTIONAL_HEADER = None
        """ Structure: Optional header.
        """

        self.section_header = list()
        """ list of Structure: Stores section headers.
        """

        self.data_directory = list()
        """ list of Structure: Stores data directories.
        """

        self.directory_entry_export = None
        """ ExportContainer: Export container.
        """

        self.directory_entry_import = None
        """ ImportContainer: Import container.
        """

        self.directory_entry_resource = None
        """ ResourceContainer: Resources container.
        """

        self.directory_entry_basereloc = None
        """ BaseRelocContainer: Relocations container.
        """

        self.directory_entry_debug = None
        """ DebugContainer: Debug information container.
        """

        self.directory_entry_tls = None
        """ TlsContainer: Thread local storage container.
        """

        self.directory_entry_load_config = None
        """ LoadConfigContainer: Load configuration container.
        """

        self.directory_entry_bound_import = None
        """ BoundImportContainer: Bound import container.
        """

        self.directory_entry_delay_import = None
        """ DelayImportContainer: Delay load import container.
        """

        # Enforce parameter constraints.
        if fname is None:
            raise ValueError('fname must be specified.')

        self.pe_size = os.stat(self.fname).st_size

        # Check if the file is empty.
        if self.pe_size == 0:
            raise IOError("File is empty.")

        try:
            with open(self.fname, 'rb') as f:
                self.data = DataContainer(
                    f.fileno(), 0, access=mmap.ACCESS_READ)

        except Exception:
            raise IOError("Unable to read file.")

        self.__parse__(self.data)

    def __str__(self) -> str:
        return self.dump()

    def __parse__(self, data: DataContainer) -> None:
        """ Parses the portable executable file.
        """

        self.hashes = data.get_hashes()

        try:

            self.DOS_HEADER = Structure(
                self.__IMAGE_DOS_HEADER__,
                'IMAGE_DOS_HEADER',
                data[:64],
                0)

        except ParseError:
            raise PEError("Unable to parse IMAGE_DOS_HEADER.")

        # Sanity check DOS header magic.
        if self.DOS_HEADER.e_magic == DOSZM_SIGNATURE:
            raise PEError("File is a ZM executable.")

        if self.DOS_HEADER.e_magic != DOS_SIGNATURE:
            raise PEError("DOS header magic not found.")

        # Bounds check e_lfanew.
        if self.DOS_HEADER.e_lfanew > self.pe_size:
            raise PEError("e_lfanew points outside of file.")

        if self.DOS_HEADER.e_lfanew == 0:
            raise PEError("e_lfanew is null.")

        if self.DOS_HEADER.e_lfanew < 4:
            raise PEError("e_lfanew is smaller than the minimum value 4.")

        if self.DOS_HEADER.e_lfanew % 4 != 0:
            raise PEError("NT headers offset must be dword aligned.")

        if self.DOS_HEADER.e_lfanew < 64:
            self.warnings.append(
                "e_lfanew points inside of the DOS header. "
                "The DOS header and NT headers are overlapping.")

        # Check if the DOS stub contains the magic string.
        if not self._contains_dos_stub(data, self.DOS_HEADER.e_lfanew):
            self.warnings.append("DOS stub does not contain magic string.")

        # TODO: parse rich header.

        p = self.DOS_HEADER.e_lfanew

        try:

            self.NT_HEADERS = Structure(
                self.__IMAGE_NT_HEADERS__,
                'IMAGE_NT_HEADERS',
                data[p:p+4],
                p)

        except ParseError:
            raise PEError("Unable to parse NT headers.")

        # Sanity check NT headers signature.
        if self.NT_HEADERS.Signature != NT_SIGNATURE:
            raise PEError("NT headers signature not found.")

        p += 4

        try:

            self.FILE_HEADER = Structure(
                self.__IMAGE_FILE_HEADER__,
                'IMAGE_FILE_HEADER',
                data[p:p+20],
                p)

        except ParseError:
            raise PEError("Unable to parse IMAGE_FILE_HEADER.")

        try:
            self.FILE_HEADER.set_other(
                'str_Machine', self.__MACHINE__[self.FILE_HEADER.Machine])

        except IndexError:
            self.warnings.append(
                'Unknown Machine specified in File header.')

        self.FILE_HEADER.set_flags(
            self.FILE_HEADER.Characteristics,
            self.__FILE_CHARACTERISTICS__)

        p += 20

        # SizeOfOptionalHeader controls the start of the sections table.
        section_offset = p + self.FILE_HEADER.SizeOfOptionalHeader

        # Check if the number of sections is anomalous.
        if self.FILE_HEADER.NumberOfSections == 0:
            self.warnings.append("NumberOfSections is null.")

        # .text/.code, .rdata, .data, .idata, .edata, .pdata, .rsrc, .reloc.
        elif self.FILE_HEADER.NumberOfSections > 8:
            self.warnings.append(
                "NumberOfSections is non-standard.")

        # Sanity check if the optional header size is standard.
        if self.FILE_HEADER.SizeOfOptionalHeader not in [224, 240]:
            self.warnings.append(
                "SizeOfOptionalHeader is non-standard. "
                "The Optional header is most likely collapsed.")

        self._parse_optional_header(data, p)

        # Since data directories are a part of the optional header, we
        # calculate the offset in the optional header where they start.
        p += self.OPTIONAL_HEADER.sizeof

        # Parse the data directory entries.
        self._parse_directory_entries(data, p)

        # Parse the section headers.
        self._parse_section_headers(data, section_offset)

        # Check whether entry point is within a section.
        if self.get_section_from_rva(
                self.OPTIONAL_HEADER.AddressOfEntryPoint) is None:
            self.warnings.append(
                "AddressOfEntryPoint points outside of sections.")

        # Check whether entry point is out of file.
        if self.OPTIONAL_HEADER.AddressOfEntryPoint > self.pe_size:
            self.warnings.append(
                "AddressOfEntryPoint points outside of the file.")

        # Parse the data directories.
        if not self.fast_load:
            self._parse_directories(data)

    def _parse_optional_header(
        self,
        data: DataContainer,
        offset: int
    ) -> None:
        """ Parses the optional header.
        """

        p = offset

        # The optional header does not require all fields, and can be
        # overlapped with the sections table. We may have to truncate
        # the optional header if the size of the PE file is too small.
        is_truncated = False

        try:

            self.OPTIONAL_HEADER = Structure(
                self.__IMAGE_OPTIONAL_HEADER__,
                'IMAGE_OPTIONAL_HEADER',
                data[p:p+96],
                p)

        except ParseError:

            try:

                self.OPTIONAL_HEADER = Structure(
                    self.__IMAGE_OPTIONAL_HEADER__,
                    'IMAGE_OPTIONAL_HEADER',
                    data[p:p+69],
                    p,
                    pad=96-69)

            except ParseError:
                PEError("Unable to parse IMAGE_OPTIONAL_HEADER.")

            is_truncated = True

        if self.OPTIONAL_HEADER.Magic == NT_OPTIONAL_HDR32_MAGIC:
            self.pe_type = NT_OPTIONAL_HDR32_MAGIC

        # We re-parse if the header magic is for 64 bit PE files.
        elif self.OPTIONAL_HEADER.Magic == NT_OPTIONAL_HDR64_MAGIC:
            self.pe_type = NT_OPTIONAL_HDR64_MAGIC

            try:

                self.OPTIONAL_HEADER = Structure(
                    self.__IMAGE_OPTIONAL_HEADER64__,
                    'IMAGE_OPTIONAL_HEADER64',
                    data[p:p+112],
                    p)

            except ParseError:

                try:

                    self.OPTIONAL_HEADER = self.Structure(
                        self.__IMAGE_OPTIONAL_HEADER64__,
                        'IMAGE_OPTIONAL_HEADER64',
                        data[p:p+73],
                        p,
                        pad=112-73)

                except ParseError:
                    PEError("Unable to parse IMAGE_OPTIONAL_HEADER.")

                is_truncated = True

        elif self.OPTIONAL_HEADER.Magic == ROM_OPTIONAL_HDR_MAGIC:
            raise PEError("The file is a ROM image.")

        else:
            raise PEError("Optional header magic is invalid.")

        # Report whether the optional header has been truncated.
        if is_truncated:
            self.warnings.append("Optional header has been truncated.")

        self.OPTIONAL_HEADER.set_flags(
            self.OPTIONAL_HEADER.DllCharacteristics,
            self.__DllCHARACTERISTICS__)

        # Sanity check whether entry point is null.
        if self.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
            self.warnings.append("AddressOfEntryPoint is null.")

        # Not null is a pre-requisite for this check.
        elif self.OPTIONAL_HEADER.AddressOfEntryPoint < \
            self.OPTIONAL_HEADER.SizeOfHeaders:
            self.warnings.append(
                "AddressOfEntryPoint is smaller than SizeOfHeaders. "
                "File can't be run on Windows 8.")

        # Sanity check if ImageBase is 10000h aligned.
        if self.OPTIONAL_HEADER.ImageBase % 0x10000 != 0:
            self.warnings.append("ImageBase is not 0x10000 aligned.")

        # Sanity check if ImageBase is null.
        if self.OPTIONAL_HEADER.ImageBase == 0:
            self.warnings.append(
                "ImageBase is null. "
                "Will be relocated to 0x10000 when loaded.")

        # Sanity check FileAlignment.
        if not 200 <= self.OPTIONAL_HEADER.FileAlignment <= \
            self.OPTIONAL_HEADER.SectionAlignment:
            self.warnings.append("FileAlignment is non-standard.")

        # Check if FileAlignment is a power of 2 (throw exception?).
        if math.ceil(math.log2(self.OPTIONAL_HEADER.FileAlignment)) != \
            math.floor(math.log2(self.OPTIONAL_HEADER.FileAlignment)):
            self.warnings.append(
                "FileAlignment is not a power of 2. "
                "The file should not be able to run.")

        # Sanity check SectionAlignment.
        if not 1000 <= self.OPTIONAL_HEADER.SectionAlignment:
            self.warnings.append("SectionAlignment is non-standard.")

        # Check if SectionAlignment is a power of 2 (throw exception?).
        if math.ceil(math.log2(self.OPTIONAL_HEADER.SectionAlignment)) != \
            math.floor(math.log2(self.OPTIONAL_HEADER.SectionAlignment)):
            self.warnings.append(
                "SectionAlignment is not a power of 2. "
                "The file should not be able to run.")

        # Check if MajorSubsystemVersion < 3.10 (throw exception?).
        if self.OPTIONAL_HEADER.MajorSubsystemVersion < 3.10:
            self.warnings.append(
                "MajorSubsystemVersion is less than 3.10. "
                "The file should not be able to run on Windows 8 or later.")

        # Sanity check the number of data directories.
        if self.OPTIONAL_HEADER.NumberOfRvaAndSizes != NUM_DATA_DIRECTORIES:
            self.warnings.append("NumberOfRvaAndSizes is non-standard.")

    def _parse_directory_entries(
        self,
        data: DataContainer,
        offset: int
    ) -> None:
        """ Parses the data directory entries.
        """

        p = offset

        # The windows loader only parses the first 16 entries.
        for idx in range(min(self.OPTIONAL_HEADER.NumberOfRvaAndSizes, 16)):

            try:

                directory = Structure(
                    self.__IMAGE_DATA_DIRECTORY__,
                    'IMAGE_DATA_DIRECTORY',
                    data[p:p+8],
                    p)

            except ParseError:
                raise PEError("Unable to parse IMAGE_DATA_DIRECTORY.")

            # Set the type of the data directory.
            directory.set_type(self.__DIRECTORY_ENTRIES__[idx])

            self.data_directory.append(directory)

            p += 8

    def _parse_section_headers(
        self,
        data: DataContainer,
        offset: int
    ) -> None:
        """ Parses the section headers.
        """

        p = offset

        # Check the number of sections.
        if self.FILE_HEADER.NumberOfSections > MAX_SECTIONS:
            self.warnings.append(
                "NumberOfSections is bigger than the parser limit. "
                "Some will not be parsed.")

        for _ in range(min(
                self.FILE_HEADER.NumberOfSections,
                MAX_SECTIONS)):

            try:

                section = Structure(
                    self.__IMAGE_SECTION_HEADER__,
                    'IMAGE_SECTION_HEADER',
                    data[p:p+40],
                    p)

            except ParseError:
                raise PEError("Unable to parse IMAGE_SECTION_HEADER.")

            # Check if section is larger than file.
            if section.PointerToRawData + section.SizeOfRawData > len(data):
                self.warnings.append(
                    'Section PointerToRawData points outside of the file.')

            # Check if PointerToRawData is file aligned.
            a = section.PointerToRawData % self.OPTIONAL_HEADER.FileAlignment

            if self.OPTIONAL_HEADER.FileAlignment != 0 and a:
                self.warnings.append(
                    'Section PointerToRawData not aligned with FileAlignment.')

            section.set_flags(
                section.Characteristics,
                self.__SCN_CHARACTERISTICS__)

            # Check if the section is both writable and executable.
            if 'IMAGE_SCN_MEM_WRITE' in section.flags \
                    and 'IMAGE_SCN_MEM_EXECUTE' in section.flags:
                self.warnings.append(
                    "Section is both writable and executable. "
                    "May indicate packing.")

            if self.is_entropy:

                # Get the entropy of the section.
                entropy = data.get_entropy(
                    section.PointerToRawData,
                    section.SizeOfRawData)

                section.set_other('flt_Entropy', entropy)

            self.section_header.append(section)

            p += 40

        # Check if sections are sorted by virtual address.
        if len(self.section_header) > 1:
            for idx in range(1, len(self.section_header)):
                if self.section_header[idx].VirtualAddress < \
                    self.section_header[idx-1].VirtualAddress:
                    self.warnings.append(
                        "Sections are not sorted by VirtualAddress.")

                    break

        # Ensure that the section headers are sorted by virtual address.
        self.section_header.sort(key=lambda s: s.VirtualAddress)

    def _parse_directories(self, data: DataContainer) -> None:
        """ Parses the data directories.
        """

        if len(self.data_directory) > 0:
            self.directory_entry_export = self._create_ExportContainer(
                data, self.data_directory[0])

        if len(self.data_directory) > 1:
            self.directory_entry_import = self._create_ImportContainer(
                data, self.data_directory[1])

        if len(self.data_directory) > 2:
            self.directory_entry_resource = self._create_ResourceContainer(
                data, self.data_directory[2])

        if len(self.data_directory) > 5:
            self.directory_entry_basereloc = self._create_BaseRelocContainer(
                data, self.data_directory[5])

        if len(self.data_directory) > 6:
            self.directory_entry_debug = self._create_DebugContainer(
                data, self.data_directory[6])

        if len(self.data_directory) > 9:
            self.directory_entry_tls = self._create_TlsContainer(
                data, self.data_directory[9])

        if len(self.data_directory) > 10:
            self.directory_entry_load_config = self._create_LoadConfigContainer(
                data, self.data_directory[10])

        if len(self.data_directory) > 11:
            self.directory_entry_bound_import = self._create_BoundImportContainer(
                data, self.data_directory[11])

        if len(self.data_directory) > 13:
            self.directory_entry_delay_import = self._create_DelayImportContainer(
                data, self.data_directory[13])

    def _contains_dos_stub(self, data: DataContainer, e_lfanew: int) -> bool:
        """ True if DOS string is found between DOS header and NT headers.
        """

        dos_string = 'This program cannot be run in DOS mode.'

        if data.find(dos_string.encode('ascii'), 64, 64+e_lfanew) > 0:
            return True

        else:
            return False

    def get_section_from_rva(self, rva: int) -> Structure:
        """ Returns the section header containing the rva or None.
        """

        if not self.section_header:
            return None

        for idx in range(len(self.section_header)):

            if self.section_header[idx].VirtualAddress > rva:

                # If rva is before the first section return None.
                if idx != 0:
                    return self.section_header[idx-1]

                return None

        # Assume it is the last section.
        return self.section_header[-1]

    def rva_to_file_offset(self, rva: int) -> int:
        """ Returns the file offset of an rva.
        """

        section = self.get_section_from_rva(rva)

        if section:

            return rva - section.VirtualAddress + section.PointerToRawData

        # If not found within a section assume rva is before the sections.
        return rva

    def dump(self) -> str:
        """ Returns a string containing all PE file information.
        """

        def format_environment() -> str:
            """ Formats environment information.
            """

            if self.fname:
                return "Parsed from -> %s\n" % self.fname

            return "Parsed from buffer.\n"

        def format_header(value: str) -> str:
            """ Formats a header.
            """

            return '# %s %s' % (value, '-' * (HEADER_LENGTH - len(value)))

        def format_helper(value: Union[Structure, list, dict]) -> str:
            """ Helper function for formatting.
            """

            if not value:
                return ''

            elif isinstance(value, list):
                value = '\n\n'.join(map(lambda d: d.__str__(), value))

            elif isinstance(value, dict):
                value = '\n\n'.join(
                    map(lambda k: '[%s]\n%s' % (k, value[k]), value))

            return '\n%s\n' % value.__str__()

        return '\n'.join([
            '',
            format_environment(),
            format_header('Warnings'),
            format_helper(self.warnings),
            format_header('File Hashes'),
            format_helper(self.hashes),
            format_header('DOS Header'),
            format_helper(self.DOS_HEADER),
            format_header('NT Headers'),
            format_helper(self.NT_HEADERS),
            format_header('File Header'),
            format_helper(self.FILE_HEADER),
            format_header('Optional Header'),
            format_helper(self.OPTIONAL_HEADER),
            format_header('Data Directory'),
            format_helper(self.data_directory),
            format_header('Section Header'),
            format_helper(self.section_header),
            format_header('Export Directory'),
            format_helper(self.directory_entry_export),
            format_header('Import Directory'),
            format_helper(self.directory_entry_import),
            format_header('Resource Directory'),
            format_helper(self.directory_entry_resource),
            format_header('Base Relocations Directory'),
            format_helper(self.directory_entry_basereloc),
            format_header('Debug Directory'),
            format_helper(self.directory_entry_debug),
            format_header('Thread Local Storage Directory'),
            format_helper(self.directory_entry_tls),
            format_header('Load Configuration Directory'),
            format_helper(self.directory_entry_load_config),
            format_header('Bound Import Directory'),
            format_helper(self.directory_entry_bound_import),
            format_header('Delay Load Import Directory'),
            format_helper(self.directory_entry_delay_import)
        ])

    def _create_ExportContainer(
        self,
        data: DataContainer,
        directory: Structure
    ) -> ExportContainer:
        """ Factory method for creating an ExportContainer.
        """

        if directory.VirtualAddress != 0:
            return PE.ExportContainer(self, data, directory)

    def _create_ImportContainer(
        self,
        data: DataContainer,
        directory: Structure
    ) -> ImportContainer:
        """ Factory method for creating an ImportContainer.
        """

        if directory.VirtualAddress != 0:
            return PE.ImportContainer(self, data, directory)

    def _create_ResourceContainer(
        self,
        data: DataContainer,
        directory: Structure
    ) -> ResourceContainer:
        """ Factory method for creating a ResourceContainer.
        """

        if directory.VirtualAddress != 0:
            return PE.ResourceContainer(self, data, directory)

    def _create_BaseRelocContainer(
        self,
        data: DataContainer,
        directory: Structure
    ) -> BaseRelocContainer:
        """ Factory method for creating a BaseRelocContainer.
        """

        if directory.VirtualAddress != 0:
            return PE.BaseRelocContainer(self, data, directory)

    def _create_DebugContainer(
        self,
        data: DataContainer,
        directory: Structure
    ) -> DebugContainer:
        """ Factory method for creating a DebugContainer.
        """

        if directory.VirtualAddress != 0:
            return PE.DebugContainer(self, data, directory)

    def _create_TlsContainer(
        self,
        data: DataContainer,
        directory: Structure
    ) -> TlsContainer:
        """ Factory method for creating a TlsContainer.
        """

        if directory.VirtualAddress != 0:
            return PE.TlsContainer(self, data, directory)

    def _create_LoadConfigContainer(
        self,
        data: DataContainer,
        directory: Structure
    ) -> LoadConfigContainer:
        """ Factory method for creating a LoadConfigContainer.
        """

        if directory.VirtualAddress != 0:
            return PE.LoadConfigContainer(self, data, directory)

    def _create_BoundImportContainer(
        self,
        data: DataContainer,
        directory: Structure
    ) -> BoundImportContainer:
        """ Factory method for creating a BoundImportContainer.
        """

        if directory.VirtualAddress != 0:
            return PE.BoundImportContainer(self, data, directory)

    def _create_DelayImportContainer(
        self,
        data: DataContainer,
        directory: Structure
    ) -> DelayImportContainer:
        """ Factory method for creating a DelayImportContainer.
        """

        if directory.VirtualAddress != 0:
            return PE.DelayImportContainer(self, data, directory)


if __name__ == '__main__':
    pass
