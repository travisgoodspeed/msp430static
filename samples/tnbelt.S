
tnbelt.hex:     file format ihex

Disassembly of section .sec1:

00004000 <.sec1>:
    4000:	31 40 00 39 	mov	#14592,	r1	;#0x3900
    4004:	b2 40 80 5a 	mov	#23168,	&0x0120	;#0x5a80
    4008:	20 01 
    400a:	3f 40 08 00 	mov	#8,	r15	;#0x0008
    400e:	0f 93       	cmp	#0,	r15	;r3 As==00
    4010:	05 24       	jz	$+12     	;abs 0x401c
    4012:	2f 83       	decd	r15		;
    4014:	9f 4f 58 42 	mov	16984(r15),4352(r15);
    4018:	00 11 
    401a:	fb 23       	jnz	$-8      	;abs 0x4012
    401c:	3f 40 08 00 	mov	#8,	r15	;#0x0008
    4020:	0f 93       	cmp	#0,	r15	;r3 As==00
    4022:	04 24       	jz	$+10     	;abs 0x402c
    4024:	1f 83       	dec	r15		;
    4026:	cf 43 08 11 	mov.b	#0,	4360(r15);r3 As==00
    402a:	fc 23       	jnz	$-6      	;abs 0x4024
    402c:	30 40 7c 40 	br	#0x407c		;
    4030:	30 40 34 40 	br	#0x4034		;
    4034:	00 13       	reti			
    4036:	05 12       	push	r5		;
    4038:	04 12       	push	r4		;
    403a:	b2 40 80 5a 	mov	#23168,	&0x0120	;#0x5a80
    403e:	20 01 
    4040:	5f 42 2a 00 	mov.b	&0x002a,r15	;0x002a
    4044:	f2 43 2a 00 	mov.b	#-1,	&0x002a	;r3 As==11
    4048:	5f 42 1a 00 	mov.b	&0x001a,r15	;0x001a
    404c:	f2 43 1a 00 	mov.b	#-1,	&0x001a	;r3 As==11
    4050:	f2 d0 1f 00 	bis.b	#31,	&0x001e	;#0x001f
    4054:	1e 00 
    4056:	5f 42 32 00 	mov.b	&0x0032,r15	;0x0032
    405a:	f2 43 32 00 	mov.b	#-1,	&0x0032	;r3 As==11
    405e:	c2 43 21 00 	mov.b	#0,	&0x0021	;r3 As==00
    4062:	f2 40 fe ff 	mov.b	#-2,	&0x0022	;#0xfffe
    4066:	22 00 
    4068:	d2 43 24 00 	mov.b	#1,	&0x0024	;r3 As==01
    406c:	d2 c3 23 00 	bic.b	#1,	&0x0023	;r3 As==01
    4070:	d2 d3 25 00 	bis.b	#1,	&0x0025	;r3 As==01
    4074:	32 d2       	eint			
    4076:	34 41       	pop	r4		;
    4078:	35 41       	pop	r5		;
    407a:	30 41       	ret			
    407c:	31 40 fe 38 	mov	#14590,	r1	;#0x38fe
    4080:	04 41       	mov	r1,	r4	;
    4082:	b0 12 36 40 	call	#16438		;#0x4036
    4086:	94 42 06 11 	mov	&0x1106,0(r4)	;0x1106
    408a:	00 00 
    408c:	b4 53 00 00 	add	#-1,	0(r4)	;r3 As==11
    4090:	b4 93 00 00 	cmp	#-1,	0(r4)	;r3 As==11
    4094:	fb 23       	jnz	$-8      	;abs 0x408c
    4096:	92 53 02 11 	inc	&0x1102		;
    409a:	b0 12 ca 40 	call	#16586		;#0x40ca
    409e:	0f 93       	cmp	#0,	r15	;r3 As==00
    40a0:	f2 23       	jnz	$-26     	;abs 0x4086
    40a2:	c2 43 31 00 	mov.b	#0,	&0x0031	;r3 As==00
    40a6:	5f 42 31 00 	mov.b	&0x0031,r15	;0x0031
    40aa:	c2 4f 1d 00 	mov.b	r15,	&0x001d	;
    40ae:	5f 42 1d 00 	mov.b	&0x001d,r15	;0x001d
    40b2:	c2 4f 19 00 	mov.b	r15,	&0x0019	;
    40b6:	5f 42 19 00 	mov.b	&0x0019,r15	;0x0019
    40ba:	c2 4f 29 00 	mov.b	r15,	&0x0029	;
    40be:	32 d0 f0 00 	bis	#240,	r2	;#0x00f0
    40c2:	e1 3f       	jmp	$-60     	;abs 0x4086
    40c4:	21 53       	incd	r1		;
    40c6:	30 40 56 42 	br	#0x4256		;
    40ca:	0b 12       	push	r11		;
    40cc:	0a 12       	push	r10		;
    40ce:	05 12       	push	r5		;
    40d0:	04 12       	push	r4		;
    40d2:	05 41       	mov	r1,	r5	;
    40d4:	35 50 0a 00 	add	#10,	r5	;#0x000a
    40d8:	31 82       	sub	#8,	r1	;r2 As==11
    40da:	04 41       	mov	r1,	r4	;
    40dc:	82 93 02 11 	cmp	#0,	&0x1102	;r3 As==00
    40e0:	0d 20       	jnz	$+28     	;abs 0x40fc
    40e2:	f2 43 00 11 	mov.b	#-1,	&0x1100	;r3 As==11
    40e6:	b2 40 10 27 	mov	#10000,	&0x1106	;#0x2710
    40ea:	06 11 
    40ec:	82 43 0e 11 	mov	#0,	&0x110e	;r3 As==00
    40f0:	82 43 0c 11 	mov	#0,	&0x110c	;r3 As==00
    40f4:	82 43 0a 11 	mov	#0,	&0x110a	;r3 As==00
    40f8:	82 43 08 11 	mov	#0,	&0x1108	;r3 As==00
    40fc:	94 42 04 11 	mov	&0x1104,6(r4)	;0x1104
    4100:	06 00 
    4102:	94 93 06 00 	cmp	#1,	6(r4)	;r3 As==01
    4106:	23 24       	jz	$+72     	;abs 0x414e
    4108:	94 93 06 00 	cmp	#1,	6(r4)	;r3 As==01
    410c:	05 28       	jnc	$+12     	;abs 0x4118
    410e:	a4 93 06 00 	cmp	#2,	6(r4)	;r3 As==10
    4112:	34 24       	jz	$+106    	;abs 0x417c
    4114:	82 43 04 11 	mov	#0,	&0x1104	;r3 As==00
    4118:	5f 42 00 11 	mov.b	&0x1100,r15	;0x1100
    411c:	8f 11       	sxt	r15		;
    411e:	0f 5f       	rla	r15		;
    4120:	c2 4f 00 11 	mov.b	r15,	&0x1100	;
    4124:	d2 42 00 11 	mov.b	&0x1100,&0x0031	;0x1100
    4128:	31 00 
    412a:	5f 42 31 00 	mov.b	&0x0031,r15	;0x0031
    412e:	c2 4f 1d 00 	mov.b	r15,	&0x001d	;
    4132:	5f 42 1d 00 	mov.b	&0x001d,r15	;0x001d
    4136:	c2 4f 19 00 	mov.b	r15,	&0x0019	;
    413a:	5f 42 19 00 	mov.b	&0x0019,r15	;0x0019
    413e:	c2 4f 29 00 	mov.b	r15,	&0x0029	;
    4142:	5f 42 00 11 	mov.b	&0x1100,r15	;0x1100
    4146:	8f 11       	sxt	r15		;
    4148:	84 4f 00 00 	mov	r15,	0(r4)	;
    414c:	61 3c       	jmp	$+196    	;abs 0x4210
    414e:	d2 42 00 11 	mov.b	&0x1100,&0x0031	;0x1100
    4152:	31 00 
    4154:	5f 42 31 00 	mov.b	&0x0031,r15	;0x0031
    4158:	c2 4f 1d 00 	mov.b	r15,	&0x001d	;
    415c:	5f 42 1d 00 	mov.b	&0x001d,r15	;0x001d
    4160:	c2 4f 19 00 	mov.b	r15,	&0x0019	;
    4164:	5f 42 19 00 	mov.b	&0x0019,r15	;0x0019
    4168:	c2 4f 29 00 	mov.b	r15,	&0x0029	;
    416c:	f2 53 00 11 	add.b	#-1,	&0x1100	;r3 As==11
    4170:	5f 42 00 11 	mov.b	&0x1100,r15	;0x1100
    4174:	8f 11       	sxt	r15		;
    4176:	84 4f 00 00 	mov	r15,	0(r4)	;
    417a:	4a 3c       	jmp	$+150    	;abs 0x4210
    417c:	1f 42 02 11 	mov	&0x1102,r15	;0x1102
    4180:	3e 40 05 00 	mov	#5,	r14	;#0x0005
    4184:	0c 4f       	mov	r15,	r12	;
    4186:	0a 4e       	mov	r14,	r10	;
    4188:	b0 12 3a 42 	call	#16954		;#0x423a
    418c:	0f 4e       	mov	r14,	r15	;
    418e:	0f 93       	cmp	#0,	r15	;r3 As==00
    4190:	04 24       	jz	$+10     	;abs 0x419a
    4192:	f4 40 de ff 	mov.b	#-34,	2(r4)	;#0xffde
    4196:	02 00 
    4198:	02 3c       	jmp	$+6      	;abs 0x419e
    419a:	c4 43 02 00 	mov.b	#0,	2(r4)	;r3 As==00
    419e:	d2 44 02 00 	mov.b	2(r4),	&0x0029	;
    41a2:	29 00 
    41a4:	1f 42 02 11 	mov	&0x1102,r15	;0x1102
    41a8:	3f f0 03 00 	and	#3,	r15	;#0x0003
    41ac:	04 24       	jz	$+10     	;abs 0x41b6
    41ae:	f4 40 ad ff 	mov.b	#-83,	3(r4)	;#0xffad
    41b2:	03 00 
    41b4:	02 3c       	jmp	$+6      	;abs 0x41ba
    41b6:	c4 43 03 00 	mov.b	#0,	3(r4)	;r3 As==00
    41ba:	d2 44 03 00 	mov.b	3(r4),	&0x0019	;
    41be:	19 00 
    41c0:	1f 42 02 11 	mov	&0x1102,r15	;0x1102
    41c4:	3e 40 03 00 	mov	#3,	r14	;#0x0003
    41c8:	0c 4f       	mov	r15,	r12	;
    41ca:	0a 4e       	mov	r14,	r10	;
    41cc:	b0 12 3a 42 	call	#16954		;#0x423a
    41d0:	0f 4e       	mov	r14,	r15	;
    41d2:	0f 93       	cmp	#0,	r15	;r3 As==00
    41d4:	04 24       	jz	$+10     	;abs 0x41de
    41d6:	f4 40 be ff 	mov.b	#-66,	4(r4)	;#0xffbe
    41da:	04 00 
    41dc:	02 3c       	jmp	$+6      	;abs 0x41e2
    41de:	c4 43 04 00 	mov.b	#0,	4(r4)	;r3 As==00
    41e2:	d2 44 04 00 	mov.b	4(r4),	&0x001d	;
    41e6:	1d 00 
    41e8:	1f 42 02 11 	mov	&0x1102,r15	;0x1102
    41ec:	1f f3       	and	#1,	r15	;r3 As==01
    41ee:	04 24       	jz	$+10     	;abs 0x41f8
    41f0:	f4 40 ef ff 	mov.b	#-17,	5(r4)	;#0xffef
    41f4:	05 00 
    41f6:	02 3c       	jmp	$+6      	;abs 0x41fc
    41f8:	c4 43 05 00 	mov.b	#0,	5(r4)	;r3 As==00
    41fc:	d2 44 05 00 	mov.b	5(r4),	&0x0031	;
    4200:	31 00 
    4202:	f2 53 00 11 	add.b	#-1,	&0x1100	;r3 As==11
    4206:	5f 42 00 11 	mov.b	&0x1100,r15	;0x1100
    420a:	8f 11       	sxt	r15		;
    420c:	84 4f 00 00 	mov	r15,	0(r4)	;
    4210:	2f 44       	mov	@r4,	r15	;
    4212:	31 52       	add	#8,	r1	;r2 As==11
    4214:	34 41       	pop	r4		;
    4216:	35 41       	pop	r5		;
    4218:	3a 41       	pop	r10		;
    421a:	3b 41       	pop	r11		;
    421c:	30 41       	ret			
    421e:	05 12       	push	r5		;
    4220:	04 12       	push	r4		;
    4222:	d2 c3 23 00 	bic.b	#1,	&0x0023	;r3 As==01
    4226:	82 43 02 11 	mov	#0,	&0x1102	;r3 As==00
    422a:	92 53 04 11 	inc	&0x1104		;
    422e:	b1 c0 f0 00 	bic	#240,	4(r1)	;#0x00f0
    4232:	04 00 
    4234:	34 41       	pop	r4		;
    4236:	35 41       	pop	r5		;
    4238:	00 13       	reti			
    423a:	0e ee       	xor	r14,	r14	;
    423c:	3b 40 11 00 	mov	#17,	r11	;#0x0011
    4240:	05 3c       	jmp	$+12     	;abs 0x424c
    4242:	0d 10       	rrc	r13		;
    4244:	0e 6e       	rlc	r14		;
    4246:	0e 9a       	cmp	r10,	r14	;
    4248:	01 28       	jnc	$+4      	;abs 0x424c
    424a:	0e 8a       	sub	r10,	r14	;
    424c:	0c 6c       	rlc	r12		;
    424e:	0d 6d       	rlc	r13		;
    4250:	1b 83       	dec	r11		;
    4252:	f7 23       	jnz	$-16     	;abs 0x4242
    4254:	30 41       	ret			
    4256:	ff 3f       	jmp	$+0      	;abs 0x4256
    4258:	ff 00       	.word	0x00ff;	????
    425a:	00 00       	beq			
    425c:	01 00       	.word	0x0001;	????
    425e:	10 27       	jz	$-478    	;abs 0x4080
Disassembly of section .sec2:

0000ffe0 <.sec2>:
    ffe0:	30 40       	interrupt service routine at 0x4030
    ffe2:	30 40       	interrupt service routine at 0x4030
    ffe4:	30 40       	interrupt service routine at 0x4030
    ffe6:	30 40       	interrupt service routine at 0x4030
    ffe8:	1e 42       	interrupt service routine at 0x421e
    ffea:	30 40       	interrupt service routine at 0x4030
    ffec:	30 40       	interrupt service routine at 0x4030
    ffee:	30 40       	interrupt service routine at 0x4030
    fff0:	30 40       	interrupt service routine at 0x4030
    fff2:	30 40       	interrupt service routine at 0x4030
    fff4:	30 40       	interrupt service routine at 0x4030
    fff6:	30 40       	interrupt service routine at 0x4030
    fff8:	30 40       	interrupt service routine at 0x4030
    fffa:	30 40       	interrupt service routine at 0x4030
    fffc:	30 40       	interrupt service routine at 0x4030
    fffe:	00 40       	interrupt service routine at 0x4000
