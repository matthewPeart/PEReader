# PEReader

<p align="center">
<img src="/figures/logo.svg" height="20%" width="20%">
</p>

A lightweight Python module for parsing Portable Executable files. The parser reports warnings of PE file anomalies and malformations that may indicate formatting abuse. Windows defined structures are accessible as attributes on the PE object (winnt.h conventions) and extra metadata is provided, e.g. hashes, entropy, set flags, and interpreted strings. Please take a look at the files [calc.exe](/examples/calc.md), [aadauthhelper.dll](/examples/aadauthhelper.md), and [tiny.exe](/examples/tiny.md) to see the features and capabilities of the parser.

## Development

We are currently walking through the advice of the [Corkami project](https://github.com/corkami/docs/blob/master/PE/PE.md) to increase its likeness w.r.t. the Windows loader. To request a new parser feature or to report a bug please submit an issue. Please feel free to contribute to the project.

## Installation

```
pip install pereader
```

## Usage

### To parse calc.exe from file:

``` 
pe = pereader.PE('calc.exe')
```

## Features & API
Structures are named in SCREAMING_CASE (capital letters), and fields are set as attributes on the respective structures in PascalCase. The field names can be found in the source code. Containers and lists storing the structures are named in snake_case, and interpreted fields are set using a variation of hungarian notation. Below is a diagram that includes the most useful parts of the API. Some of the patterns listed below make accessing specific structures and fields easier.

<p align="center">
<img src="/figures/diagram.svg" height="85%" width="85%">
</p>

### Characteristics:

Flags are set as booleans on the respective header and true flags are stored in .flags.

### Entropy:

Entropy calculations set on the section headers can be slow for very big files. To switch them off:

``` 
pe = pereader.PE('calc.exe', is_entropy=False)
```

### Exports access pattern:

```
for exp in pe.directory_entry_export.symbols:
    print(hex(exp.address), exp.name, exp.ordinal)
```

Addresses are also set directly on symbols.

```
print(pe.directory_entry_export.symbols.CreateTokenAuthBuffer)
```

### Imports access pattern:

```
for dll in pe.directory_entry_import.dlls:
    print(dll.name)
    for imp in dll:
	print(hex(imp.address), imp.name)
```

Addresses are also set directly on dlls.

```
for dll in pe.directory_entry_import.dlls:
    if hasattr(dll, 'memmove'):
        print(dll.memmove)
```

### Strings table access pattern (using shortcut):

```
for entry in pe.directory_entry_resource.resource_directory.entries:
    if entry.RESOURCE_DIRECTORY_ENTRY.str_Type == 'RT_STRING':
        for k in entry.strings:
	    print(k, entry.strings[k])
```

### Version information access pattern (using shortcut):

```
for entry in pe.directory_entry_resource.resource_directory.entries:
    if entry.RESOURCE_DIRECTORY_ENTRY.str_Type == 'RT_VERSION':
    	version = entry.version
	
	for e in version.stringfileinfo:
	    for stringtable in e.stringtables:
	        for string in stringtable.strings:
		    print(string.str_szKey, string.str_Value)
		    
	for e in version.varfileinfo:
	    for var in e.vars:
	        for w1, w2 in var.translations:
		    print(w1, w2)
```

### Relocations access pattern:

```
for reloc in pe.directory_entry_basereloc.relocations:
    for target in reloc.targets:
        print(target.Value, target.str_Type)
```

### Debug access pattern:

```
for entry in pe.directory_entry_debug.entries:
    print(entry.DEBUG_DIRECTORY.str_Type)
    print(entry.ENTRY)
```

### Thread local storage access pattern:

```
print(pe.directory_entry_tls.TLS_DIRECTORY)
```

### Load configuration access pattern:

```
print(pe.directory_entry_load_config.LOAD_CONFIG_DIRECTORY)
```

### Bound import access pattern:

```
for desc in pe.directory_entry_bound_import.descriptors:
    print(desc.str_Name, desc)
```

### Delay load access pattern:

```
for dll in pe.directory_entry_delay_import.dlls:
    print(dll.name)
    for imp in dll:
	print(hex(imp.address), imp.name)
```

## Resources
Windows Dev Center specification - https://docs.microsoft.com/en-us/windows/win32/debug/pe-format  
Win32 definitions - https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-tools/widl/include/winnt.h  
PE format course - http://opensecuritytraining.info/LifeOfBinaries.html  
Resources directory - http://www.skynet.ie/~caolan/publink/winresdump/winresdump/doc/resfmt.txt  
Version information - http://blog.dkbza.org/2007/02/pefile-parsing-version-information-from.html?view=classic  
Debug directory - http://www.debuginfo.com/articles/debuginfomatch.html
