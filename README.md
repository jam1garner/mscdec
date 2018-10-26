# mscdec

MSC bytecode to C Decompiler

**Note:** Not all assembly has an accurate representation in C. Attempting to decompile hand-written assembly (such as code modified with pymsc poorly) may not decompile.

### Usage

```
mscdec.py [-h] [-o FILENAME] file

"-h" : show help text
"-o [FILENAME]" : output file (default is the same as input file with extension changed to .c)
"file" : input file to decompile
```

### License

mscdec is MIT Licensed so feel free to copy/modify/whatever. More info in `LICENSE`

### Miscellaneous Info

[Updates will be posted to my twitter](https://twitter.com/jam1garner)

Want to attempt to recompile? Check out my compiler: https://github.com/jam1garner/msclang

Need to report bugs? Submit them to the Issues tab and if I don't notice them DM me on twitter in case I missed it.