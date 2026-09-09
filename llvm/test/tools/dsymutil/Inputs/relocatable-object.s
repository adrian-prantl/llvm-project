	.section	__TEXT,__text,regular,pure_instructions
	.att_syntax
	.globl	_g_func                         ## -- Begin function g_func
	.p2align	4
_g_func:                                ## @g_func
Lfunc_begin0:
	.file	1 "/tmp" "reloc-obj.c"
	.loc	1 3 0                           ## reloc-obj.c:3:0
	.cfi_startproc
## %bb.0:                               ## %entry
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movl	%edi, -4(%rbp)
Ltmp0:
	.loc	1 3 34 prologue_end             ## reloc-obj.c:3:34
	movl	-4(%rbp), %eax
	.loc	1 3 36 is_stmt 0                ## reloc-obj.c:3:36
	andl	$3, %eax
	.loc	1 3 28                          ## reloc-obj.c:3:28
	movslq	%eax, %rcx
	leaq	_g_var(%rip), %rax
	movl	(%rax,%rcx,4), %eax
	.loc	1 3 41                          ## reloc-obj.c:3:41
	addl	_s_var(%rip), %eax
	.loc	1 3 21 epilogue_begin           ## reloc-obj.c:3:21
	popq	%rbp
	retq
Ltmp1:
Lfunc_end0:
	.cfi_endproc
                                        ## -- End function
	.globl	_g_other                        ## -- Begin function g_other
	.p2align	4
_g_other:                               ## @g_other
Lfunc_begin1:
	.loc	1 4 0 is_stmt 1                 ## reloc-obj.c:4:0
	.cfi_startproc
## %bb.0:                               ## %entry
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movl	%edi, -4(%rbp)
Ltmp2:
	.loc	1 4 31 prologue_end             ## reloc-obj.c:4:31
	imull	$3, -4(%rbp), %eax
	.loc	1 4 22 epilogue_begin is_stmt 0 ## reloc-obj.c:4:22
	popq	%rbp
	retq
Ltmp3:
Lfunc_end1:
	.cfi_endproc
                                        ## -- End function
	.section	__DATA,__data
	.globl	_g_var                          ## @g_var
	.p2align	4, 0x0
_g_var:
	.long	1                               ## 0x1
	.long	2                               ## 0x2
	.long	3                               ## 0x3
	.long	4                               ## 0x4

	.p2align	2, 0x0                          ## @s_var
_s_var:
	.long	7                               ## 0x7

	.section	__DWARF,__debug_abbrev,regular,debug
Lsection_abbrev:
	.byte	1                               ## Abbreviation Code
	.byte	17                              ## DW_TAG_compile_unit
	.byte	1                               ## DW_CHILDREN_yes
	.byte	37                              ## DW_AT_producer
	.byte	14                              ## DW_FORM_strp
	.byte	19                              ## DW_AT_language
	.byte	5                               ## DW_FORM_data2
	.byte	3                               ## DW_AT_name
	.byte	14                              ## DW_FORM_strp
	.ascii	"\202|"                         ## DW_AT_LLVM_sysroot
	.byte	14                              ## DW_FORM_strp
	.byte	16                              ## DW_AT_stmt_list
	.byte	23                              ## DW_FORM_sec_offset
	.byte	27                              ## DW_AT_comp_dir
	.byte	14                              ## DW_FORM_strp
	.byte	17                              ## DW_AT_low_pc
	.byte	1                               ## DW_FORM_addr
	.byte	18                              ## DW_AT_high_pc
	.byte	6                               ## DW_FORM_data4
	.byte	0                               ## EOM(1)
	.byte	0                               ## EOM(2)
	.byte	2                               ## Abbreviation Code
	.byte	46                              ## DW_TAG_subprogram
	.byte	1                               ## DW_CHILDREN_yes
	.byte	17                              ## DW_AT_low_pc
	.byte	1                               ## DW_FORM_addr
	.byte	18                              ## DW_AT_high_pc
	.byte	6                               ## DW_FORM_data4
	.byte	64                              ## DW_AT_frame_base
	.byte	24                              ## DW_FORM_exprloc
	.byte	3                               ## DW_AT_name
	.byte	14                              ## DW_FORM_strp
	.byte	58                              ## DW_AT_decl_file
	.byte	11                              ## DW_FORM_data1
	.byte	59                              ## DW_AT_decl_line
	.byte	11                              ## DW_FORM_data1
	.byte	39                              ## DW_AT_prototyped
	.byte	25                              ## DW_FORM_flag_present
	.byte	73                              ## DW_AT_type
	.byte	19                              ## DW_FORM_ref4
	.byte	63                              ## DW_AT_external
	.byte	25                              ## DW_FORM_flag_present
	.byte	0                               ## EOM(1)
	.byte	0                               ## EOM(2)
	.byte	3                               ## Abbreviation Code
	.byte	5                               ## DW_TAG_formal_parameter
	.byte	0                               ## DW_CHILDREN_no
	.byte	2                               ## DW_AT_location
	.byte	24                              ## DW_FORM_exprloc
	.byte	3                               ## DW_AT_name
	.byte	14                              ## DW_FORM_strp
	.byte	58                              ## DW_AT_decl_file
	.byte	11                              ## DW_FORM_data1
	.byte	59                              ## DW_AT_decl_line
	.byte	11                              ## DW_FORM_data1
	.byte	73                              ## DW_AT_type
	.byte	19                              ## DW_FORM_ref4
	.byte	0                               ## EOM(1)
	.byte	0                               ## EOM(2)
	.byte	4                               ## Abbreviation Code
	.byte	52                              ## DW_TAG_variable
	.byte	0                               ## DW_CHILDREN_no
	.byte	3                               ## DW_AT_name
	.byte	14                              ## DW_FORM_strp
	.byte	73                              ## DW_AT_type
	.byte	19                              ## DW_FORM_ref4
	.byte	63                              ## DW_AT_external
	.byte	25                              ## DW_FORM_flag_present
	.byte	58                              ## DW_AT_decl_file
	.byte	11                              ## DW_FORM_data1
	.byte	59                              ## DW_AT_decl_line
	.byte	11                              ## DW_FORM_data1
	.byte	2                               ## DW_AT_location
	.byte	24                              ## DW_FORM_exprloc
	.byte	0                               ## EOM(1)
	.byte	0                               ## EOM(2)
	.byte	5                               ## Abbreviation Code
	.byte	1                               ## DW_TAG_array_type
	.byte	1                               ## DW_CHILDREN_yes
	.byte	73                              ## DW_AT_type
	.byte	19                              ## DW_FORM_ref4
	.byte	0                               ## EOM(1)
	.byte	0                               ## EOM(2)
	.byte	6                               ## Abbreviation Code
	.byte	33                              ## DW_TAG_subrange_type
	.byte	0                               ## DW_CHILDREN_no
	.byte	73                              ## DW_AT_type
	.byte	19                              ## DW_FORM_ref4
	.byte	55                              ## DW_AT_count
	.byte	11                              ## DW_FORM_data1
	.byte	0                               ## EOM(1)
	.byte	0                               ## EOM(2)
	.byte	7                               ## Abbreviation Code
	.byte	36                              ## DW_TAG_base_type
	.byte	0                               ## DW_CHILDREN_no
	.byte	3                               ## DW_AT_name
	.byte	14                              ## DW_FORM_strp
	.byte	62                              ## DW_AT_encoding
	.byte	11                              ## DW_FORM_data1
	.byte	11                              ## DW_AT_byte_size
	.byte	11                              ## DW_FORM_data1
	.byte	0                               ## EOM(1)
	.byte	0                               ## EOM(2)
	.byte	8                               ## Abbreviation Code
	.byte	36                              ## DW_TAG_base_type
	.byte	0                               ## DW_CHILDREN_no
	.byte	3                               ## DW_AT_name
	.byte	14                              ## DW_FORM_strp
	.byte	11                              ## DW_AT_byte_size
	.byte	11                              ## DW_FORM_data1
	.byte	62                              ## DW_AT_encoding
	.byte	11                              ## DW_FORM_data1
	.byte	0                               ## EOM(1)
	.byte	0                               ## EOM(2)
	.byte	9                               ## Abbreviation Code
	.byte	52                              ## DW_TAG_variable
	.byte	0                               ## DW_CHILDREN_no
	.byte	3                               ## DW_AT_name
	.byte	14                              ## DW_FORM_strp
	.byte	73                              ## DW_AT_type
	.byte	19                              ## DW_FORM_ref4
	.byte	58                              ## DW_AT_decl_file
	.byte	11                              ## DW_FORM_data1
	.byte	59                              ## DW_AT_decl_line
	.byte	11                              ## DW_FORM_data1
	.byte	2                               ## DW_AT_location
	.byte	24                              ## DW_FORM_exprloc
	.byte	0                               ## EOM(1)
	.byte	0                               ## EOM(2)
	.byte	0                               ## EOM(3)
	.section	__DWARF,__debug_info,regular,debug
Lsection_info:
Lcu_begin0:
Lset0 = Ldebug_info_end0-Ldebug_info_start0 ## Length of Unit
	.long	Lset0
Ldebug_info_start0:
	.short	4                               ## DWARF version number
Lset1 = Lsection_abbrev-Lsection_abbrev ## Offset Into Abbrev. Section
	.long	Lset1
	.byte	8                               ## Address Size (in bytes)
	.byte	1                               ## Abbrev [1] 0xb:0xb8 DW_TAG_compile_unit
	.long	0                               ## DW_AT_producer
	.short	29                              ## DW_AT_language
	.long	104                             ## DW_AT_name
	.long	116                             ## DW_AT_LLVM_sysroot
Lset2 = Lline_table_start0-Lsection_line ## DW_AT_stmt_list
	.long	Lset2
	.long	118                             ## DW_AT_comp_dir
	.quad	Lfunc_begin0                    ## DW_AT_low_pc
Lset3 = Lfunc_end1-Lfunc_begin0         ## DW_AT_high_pc
	.long	Lset3
	.byte	2                               ## Abbrev [2] 0x2e:0x28 DW_TAG_subprogram
	.quad	Lfunc_begin0                    ## DW_AT_low_pc
Lset4 = Lfunc_end0-Lfunc_begin0         ## DW_AT_high_pc
	.long	Lset4
	.byte	1                               ## DW_AT_frame_base
	.byte	86
	.long	123                             ## DW_AT_name
	.byte	1                               ## DW_AT_decl_file
	.byte	3                               ## DW_AT_decl_line
                                        ## DW_AT_prototyped
	.long	159                             ## DW_AT_type
                                        ## DW_AT_external
	.byte	3                               ## Abbrev [3] 0x47:0xe DW_TAG_formal_parameter
	.byte	2                               ## DW_AT_location
	.byte	145
	.byte	124
	.long	174                             ## DW_AT_name
	.byte	1                               ## DW_AT_decl_file
	.byte	3                               ## DW_AT_decl_line
	.long	159                             ## DW_AT_type
	.byte	0                               ## End Of Children Mark
	.byte	2                               ## Abbrev [2] 0x56:0x28 DW_TAG_subprogram
	.quad	Lfunc_begin1                    ## DW_AT_low_pc
Lset5 = Lfunc_end1-Lfunc_begin1         ## DW_AT_high_pc
	.long	Lset5
	.byte	1                               ## DW_AT_frame_base
	.byte	86
	.long	130                             ## DW_AT_name
	.byte	1                               ## DW_AT_decl_file
	.byte	4                               ## DW_AT_decl_line
                                        ## DW_AT_prototyped
	.long	159                             ## DW_AT_type
                                        ## DW_AT_external
	.byte	3                               ## Abbrev [3] 0x6f:0xe DW_TAG_formal_parameter
	.byte	2                               ## DW_AT_location
	.byte	145
	.byte	124
	.long	174                             ## DW_AT_name
	.byte	1                               ## DW_AT_decl_file
	.byte	4                               ## DW_AT_decl_line
	.long	159                             ## DW_AT_type
	.byte	0                               ## End Of Children Mark
	.byte	4                               ## Abbrev [4] 0x7e:0x15 DW_TAG_variable
	.long	138                             ## DW_AT_name
	.long	147                             ## DW_AT_type
                                        ## DW_AT_external
	.byte	1                               ## DW_AT_decl_file
	.byte	1                               ## DW_AT_decl_line
	.byte	9                               ## DW_AT_location
	.byte	3
	.quad	_g_var
	.byte	5                               ## Abbrev [5] 0x93:0xc DW_TAG_array_type
	.long	159                             ## DW_AT_type
	.byte	6                               ## Abbrev [6] 0x98:0x6 DW_TAG_subrange_type
	.long	166                             ## DW_AT_type
	.byte	4                               ## DW_AT_count
	.byte	0                               ## End Of Children Mark
	.byte	7                               ## Abbrev [7] 0x9f:0x7 DW_TAG_base_type
	.long	144                             ## DW_AT_name
	.byte	5                               ## DW_AT_encoding
	.byte	4                               ## DW_AT_byte_size
	.byte	8                               ## Abbrev [8] 0xa6:0x7 DW_TAG_base_type
	.long	148                             ## DW_AT_name
	.byte	8                               ## DW_AT_byte_size
	.byte	7                               ## DW_AT_encoding
	.byte	9                               ## Abbrev [9] 0xad:0x15 DW_TAG_variable
	.long	168                             ## DW_AT_name
	.long	159                             ## DW_AT_type
	.byte	1                               ## DW_AT_decl_file
	.byte	2                               ## DW_AT_decl_line
	.byte	9                               ## DW_AT_location
	.byte	3
	.quad	_s_var
	.byte	0                               ## End Of Children Mark
Ldebug_info_end0:
	.section	__DWARF,__debug_str,regular,debug
Linfo_string:
	.asciz	"clang version 24.0.0git (git@github.com:llvm/llvm-project.git cc5c51457347547dbac6edcfe9887ca5aeee1b3d)" ## string offset=0 ; clang version 24.0.0git (git@github.com:llvm/llvm-project.git cc5c51457347547dbac6edcfe9887ca5aeee1b3d)
	.asciz	"reloc-obj.c"                   ## string offset=104 ; reloc-obj.c
	.asciz	"/"                             ## string offset=116 ; /
	.asciz	"/tmp"                          ## string offset=118 ; /tmp
	.asciz	"g_func"                        ## string offset=123 ; g_func
	.asciz	"g_other"                       ## string offset=130 ; g_other
	.asciz	"g_var"                         ## string offset=138 ; g_var
	.asciz	"int"                           ## string offset=144 ; int
	.asciz	"__ARRAY_SIZE_TYPE__"           ## string offset=148 ; __ARRAY_SIZE_TYPE__
	.asciz	"s_var"                         ## string offset=168 ; s_var
	.asciz	"v"                             ## string offset=174 ; v
	.section	__DWARF,__apple_names,regular,debug
Lnames_begin:
	.long	1212240712                      ## Header Magic
	.short	1                               ## Header Version
	.short	0                               ## Header Hash Function
	.long	4                               ## Header Bucket Count
	.long	4                               ## Header Hash Count
	.long	12                              ## Header Data Length
	.long	0                               ## HeaderData Die Offset Base
	.long	1                               ## HeaderData Atom Count
	.short	1                               ## DW_ATOM_die_offset
	.short	6                               ## DW_FORM_data4
	.long	0                               ## Bucket 0
	.long	2                               ## Bucket 1
	.long	-1                              ## Bucket 2
	.long	3                               ## Bucket 3
	.long	259847924                       ## Hash in Bucket 0
	.long	274078976                       ## Hash in Bucket 0
	.long	-501078387                      ## Hash in Bucket 1
	.long	-15506345                       ## Hash in Bucket 3
Lset6 = LNames0-Lnames_begin            ## Offset in Bucket 0
	.long	Lset6
Lset7 = LNames1-Lnames_begin            ## Offset in Bucket 0
	.long	Lset7
Lset8 = LNames2-Lnames_begin            ## Offset in Bucket 1
	.long	Lset8
Lset9 = LNames3-Lnames_begin            ## Offset in Bucket 3
	.long	Lset9
LNames0:
	.long	138                             ## g_var
	.long	1                               ## Num DIEs
	.long	126
	.long	0
LNames1:
	.long	168                             ## s_var
	.long	1                               ## Num DIEs
	.long	173
	.long	0
LNames2:
	.long	130                             ## g_other
	.long	1                               ## Num DIEs
	.long	86
	.long	0
LNames3:
	.long	123                             ## g_func
	.long	1                               ## Num DIEs
	.long	46
	.long	0
	.section	__DWARF,__apple_objc,regular,debug
Lobjc_begin:
	.long	1212240712                      ## Header Magic
	.short	1                               ## Header Version
	.short	0                               ## Header Hash Function
	.long	1                               ## Header Bucket Count
	.long	0                               ## Header Hash Count
	.long	12                              ## Header Data Length
	.long	0                               ## HeaderData Die Offset Base
	.long	1                               ## HeaderData Atom Count
	.short	1                               ## DW_ATOM_die_offset
	.short	6                               ## DW_FORM_data4
	.long	-1                              ## Bucket 0
	.section	__DWARF,__apple_namespac,regular,debug
Lnamespac_begin:
	.long	1212240712                      ## Header Magic
	.short	1                               ## Header Version
	.short	0                               ## Header Hash Function
	.long	1                               ## Header Bucket Count
	.long	0                               ## Header Hash Count
	.long	12                              ## Header Data Length
	.long	0                               ## HeaderData Die Offset Base
	.long	1                               ## HeaderData Atom Count
	.short	1                               ## DW_ATOM_die_offset
	.short	6                               ## DW_FORM_data4
	.long	-1                              ## Bucket 0
	.section	__DWARF,__apple_types,regular,debug
Ltypes_begin:
	.long	1212240712                      ## Header Magic
	.short	1                               ## Header Version
	.short	0                               ## Header Hash Function
	.long	2                               ## Header Bucket Count
	.long	2                               ## Header Hash Count
	.long	20                              ## Header Data Length
	.long	0                               ## HeaderData Die Offset Base
	.long	3                               ## HeaderData Atom Count
	.short	1                               ## DW_ATOM_die_offset
	.short	6                               ## DW_FORM_data4
	.short	3                               ## DW_ATOM_die_tag
	.short	5                               ## DW_FORM_data2
	.short	4                               ## DW_ATOM_type_flags
	.short	11                              ## DW_FORM_data1
	.long	0                               ## Bucket 0
	.long	1                               ## Bucket 1
	.long	193495088                       ## Hash in Bucket 0
	.long	-594775205                      ## Hash in Bucket 1
Lset10 = Ltypes0-Ltypes_begin           ## Offset in Bucket 0
	.long	Lset10
Lset11 = Ltypes1-Ltypes_begin           ## Offset in Bucket 1
	.long	Lset11
Ltypes0:
	.long	144                             ## int
	.long	1                               ## Num DIEs
	.long	159
	.short	36
	.byte	0
	.long	0
Ltypes1:
	.long	148                             ## __ARRAY_SIZE_TYPE__
	.long	1                               ## Num DIEs
	.long	166
	.short	36
	.byte	0
	.long	0
.subsections_via_symbols
	.section	__DWARF,__debug_line,regular,debug
Lsection_line:
Lline_table_start0:

## A section after the DWARF, holding a symbol. Emitting the linked DWARF drops
## the input's own __DWARF sections, which renumbers everything following them;
## this symbol catches a stale section index being copied through.
	.section	__CUSTOM,__trailing
	.globl	_trailing_sym
_trailing_sym:
	.quad	0
