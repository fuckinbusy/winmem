	.file	"test.c"
	.text
	.section .rdata,"dr"
.LC0:
	.ascii "WinMem Engine Magic\0"
	.text
	.globl	wmscfns__shellcodeTest
	.def	wmscfns__shellcodeTest;	.scl	2;	.type	32;	.endef
	.seh_proc	wmscfns__shellcodeTest
wmscfns__shellcodeTest:
	pushq	%rbp
	.seh_pushreg	%rbp
	movq	%rsp, %rbp
	.seh_setframe	%rbp, 0
	subq	$64, %rsp
	.seh_stackalloc	64
	.seh_endprologue
	movq	%rcx, 16(%rbp)
	movq	16(%rbp), %rax
	movq	%rax, -8(%rbp)
	cmpq	$0, -8(%rbp)
	je	.L4
	movq	-8(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -16(%rbp)
	movq	-8(%rbp), %rax
	addq	$256, %rax
	movq	%rax, -24(%rbp)
	cmpq	$0, -16(%rbp)
	je	.L1
	leaq	.LC0(%rip), %rdx
	movq	-24(%rbp), %rax
	movq	-16(%rbp), %r10
	movl	$0, %r9d
	movq	%rdx, %r8
	movq	%rax, %rdx
	movl	$0, %ecx
	call	*%r10
	jmp	.L1
.L4:
	nop
.L1:
	addq	$64, %rsp
	popq	%rbp
	ret
	.seh_endproc
	.globl	wmscfne__shellcodeTest
	.def	wmscfne__shellcodeTest;	.scl	2;	.type	32;	.endef
	.seh_proc	wmscfne__shellcodeTest
wmscfne__shellcodeTest:
	pushq	%rbp
	.seh_pushreg	%rbp
	movq	%rsp, %rbp
	.seh_setframe	%rbp, 0
	subq	$16, %rsp
	.seh_stackalloc	16
	.seh_endprologue
	movl	$0, -4(%rbp)
	nop
	addq	$16, %rsp
	popq	%rbp
	ret
	.seh_endproc
	.section .rdata,"dr"
	.align 2
.LC1:
	.ascii "p\0r\0o\0g\0r\0a\0m\0.\0e\0x\0e\0\0\0"
	.align 8
.LC2:
	.ascii "shellcode injected successfully =D\0"
.LC3:
	.ascii "MessageBoxA\0"
.LC4:
	.ascii "user32.dll\0"
	.text
	.globl	main
	.def	main;	.scl	2;	.type	32;	.endef
	.seh_proc	main
main:
	pushq	%rbp
	.seh_pushreg	%rbp
	movq	%rsp, %rbp
	.seh_setframe	%rbp, 0
	subq	$48, %rsp
	.seh_stackalloc	48
	.seh_endprologue
	call	__main
	leaq	.LC1(%rip), %rdx
	leaq	-8(%rbp), %rax
	movl	$2097151, %r8d
	movq	%rax, %rcx
	call	wmProcessOpen
	movl	%eax, -4(%rbp)
	movq	$0, -16(%rbp)
	leaq	-16(%rbp), %rax
	movq	%rax, %rcx
	call	wmShellcodeCreate
	movq	-16(%rbp), %rax
	leaq	.LC2(%rip), %rdx
	movq	%rax, %rcx
	call	wmShellcodeAddString
	movq	-16(%rbp), %rax
	leaq	.LC3(%rip), %rcx
	leaq	.LC4(%rip), %rdx
	movq	%rcx, %r8
	movq	%rax, %rcx
	call	wmShellcodeAddFunction
	movq	-16(%rbp), %rax
	leaq	wmscfne__shellcodeTest(%rip), %rcx
	leaq	wmscfns__shellcodeTest(%rip), %rdx
	movq	%rcx, %r8
	movq	%rax, %rcx
	call	wmShellcodeSetPayload
	movq	-16(%rbp), %rdx
	movl	-8(%rbp), %eax
	movl	%eax, %ecx
	call	wmShellcodeExecute
	movq	-16(%rbp), %rax
	movq	%rax, %rcx
	call	wmShellcodeDestroy
	movl	-8(%rbp), %eax
	movl	%eax, %ecx
	call	wmProcessClose
	movl	-4(%rbp), %eax
	addq	$48, %rsp
	popq	%rbp
	ret
	.seh_endproc
	.def	__main;	.scl	2;	.type	32;	.endef
	.ident	"GCC: (Rev8, Built by MSYS2 project) 15.2.0"
	.def	wmProcessOpen;	.scl	2;	.type	32;	.endef
	.def	wmShellcodeCreate;	.scl	2;	.type	32;	.endef
	.def	wmShellcodeAddString;	.scl	2;	.type	32;	.endef
	.def	wmShellcodeAddFunction;	.scl	2;	.type	32;	.endef
	.def	wmShellcodeSetPayload;	.scl	2;	.type	32;	.endef
	.def	wmShellcodeExecute;	.scl	2;	.type	32;	.endef
	.def	wmShellcodeDestroy;	.scl	2;	.type	32;	.endef
	.def	wmProcessClose;	.scl	2;	.type	32;	.endef
