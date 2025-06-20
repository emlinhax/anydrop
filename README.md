# anydrop
copy a file anywhere. \
uac will skip for most folders (e.g C:\Program Files)

# how?
we act as explorer.exe to bypass some restrictions on file moving. \
 \
for the knowing ones: \
PEB Masquerading + IFileOperation

# usage
```cpp
anydrop::init();
anydrop::move(src_path, dest_path, TRUE); // TRUE = copy | FALSE = move
```
