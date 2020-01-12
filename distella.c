#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define IMPLIED		0
#define ACCUMULATOR	1
#define IMMEDIATE	2

#define ZERO_PAGE	3
#define ZERO_PAGE_X	4
#define ZERO_PAGE_Y	5

#define ABSOLUTE	6
#define ABSOLUTE_X	7
#define ABSOLUTE_Y	8

#define ABS_INDIRECT    9
#define INDIRECT_X	10
#define INDIRECT_Y	11

#define RELATIVE	12

#define ASS_CODE	13

/* Marked bits
This is a reference sheet of bits that can be set for a given address, which
are stored in the labels[] array.
*/

#define REFERENCED 1	/* code somewhere in the program references it, i.e. LDA $F372 referenced $F372 */
#define VALID_ENTRY 2	/* addresses that can have a label placed in front of it. A good counterexample
                           would be "FF00: LDA $FE00"; $FF01 would be in the middle of a multi-byte
                           instruction, and therefore cannot be labelled. */
#define DATA 4
#define GFX  8
#define REACHABLE 16	/* disassemble-able code segments */

#define BYTE 		unsigned char
#define ADDRESS 	unsigned int

/* Boolean definitions for Atari 7800 header presence */
#define NO_HEADER	0
#define YES_HEADER	1

extern int clength[];

struct resource {
	ADDRESS start;
	ADDRESS load;
        unsigned int length;
	ADDRESS end;
	int disp_data;
} app_data;

/* Memory */
BYTE *mem = NULL;	/* copied data from the file-- can be from 2K-48K bytes in size */
BYTE *labels = NULL;	/* array of information about addresses-- can be from 2K-48K bytes in size */
BYTE *hdr78 = NULL;	/* Atari 7800 header block (128 bytes, if allocated) */

BYTE reserved[64];
BYTE ioresrvd[24];
BYTE pokresvd[16];
char orgmnc[16],linebuff[80],nextline[80];
FILE *cfg;

unsigned long pc,pcbeg,pcend,offset,brk_adr,start_adr,isr_adr,k;
int aflag,cflag,dflag,fflag,pflag,rflag,sflag,intflag,a78flag,bflag,kflag,lineno,charcnt,hdr_exists;

struct qnode *addressq;

/* Prototypes */

void disasm(unsigned long,int);
int check_bit(BYTE, int);
unsigned int read_adr(void);
int load_config(char *);
void showgfx(unsigned char);
void check_range(unsigned int, unsigned int);
int mark(unsigned long,int);
unsigned int filesize(FILE *stream);
int file_load(char[]);

char stella[62][10] = 
{"VSYNC",
"VBLANK",
"WSYNC",
"RSYNC",
"NUSIZ0",
"NUSIZ1",
"COLUP0",
"COLUP1",
"COLUPF",
"COLUBK",
"CTRLPF",
"REFP0",
"REFP1",
"PF0",
"PF1",
"PF2",
"RESP0",
"RESP1",
"RESM0",
"RESM1",
"RESBL",
"AUDC0",
"AUDC1",
"AUDF0",
"AUDF1",
"AUDV0",
"AUDV1",
"GRP0",
"GRP1",
"ENAM0",
"ENAM1",
"ENABL",
"HMP0",
"HMP1",
"HMM0",
"HMM1",
"HMBL",
"VDELP0",
"VDELP1",
"VDELBL",
"RESMP0",
"RESMP1",
"HMOVE",
"HMCLR",
"CXCLR",
"$2D",
"$2E",
"$2F",
"CXM0P",
"CXM1P",
"CXP0FB",
"CXP1FB",
"CXM0FB",
"CXM1FB",
"CXBLPF",
"CXPPMM",
"INPT0",
"INPT1",
"INPT2",
"INPT3",
"INPT4",
"INPT5"};

char ioregs[24][10] =
{"SWCHA",
"SWACNT",
"SWCHB",
"SWBCNT",
"INTIM",
"$0285",
"$0286",
"$0287",
"$0288",
"$0289",
"$028A",
"$028B",
"$028C",
"$028D",
"$028E",
"$028F",
"$0290",
"$0291",
"$0292",
"$0293",
"TIM1T",
"TIM8T",
"TIM64T",
"T1024T"};

char maria[64][10] = 
{"$00",
"INPTCTRL",
"$02",
"$03",
"$04",
"$05",
"$06",
"$07",
"INPT0",
"INPT1",
"INPT2",
"INPT3",
"INPT4",
"INPT5",
"$0E",
"$0F",
"$10",
"$11",
"$12",
"$13",
"$14",
"AUDC0",
"AUDC1",
"AUDF0",
"AUDF1",
"AUDV0",
"AUDV1",
"$1B",
"$1C",
"$1D",
"$1E",
"$1F",
"BACKGRND",
"P0C1",
"P0C2",
"P0C3",
"WSYNC",
"P1C1",
"P1C2",
"P1C3",
"MSTAT",
"P2C1",
"P2C2",
"P2C3",
"DPPH",
"P3C1",
"P3C2",
"P3C3",
"DPPL",
"P4C1",
"P4C2",
"P4C3",
"CHBASE",
"P5C1",
"P5C2",
"P5C3",
"OFFSET",
"P6C1",
"P6C2",
"P6C3",
"CTRL",
"P7C1",
"P7C2",
"P7C3"};

char mariaio[4][10] =
{"SWCHA",
"SWACNT",
"SWCHB",
"SWBCNT"};

char pokey[16][10] =
{"AUDF2",
"AUDC2",
"AUDF3",
"AUDC3",
"AUDF4",
"AUDC4",
"AUDF5",
"AUDC5",
"AUDCTL",
"$4009",
"RANDOM",
"$400B",
"$400C",
"$400D",
"$400E",
"SKCTLS"};

struct lookup_tag {
	char          *mnemonic;	/* Selfdocumenting? */
	short          addr_mode;
	unsigned char  source;
	unsigned char  destination;
	unsigned char  cycles;
	unsigned char  pbc_fix;	/* Cycle for Page Boundary Crossing */
};


/* Addressing mode (addr_mode) is used when instruction is diassembled
 * or assembled by diassembler or assembler. This is used i.e.
 * in function char *sprint_opcode() in the file misc.c.
 *
 * MOS6502 addressing modes are #defined in the file "vmachine.h".
 *
 * Mnemonic is character string telling the name of the instruction.
 */

#define M_NONE	0
#define M_AC 	1
#define M_XR	2
#define M_YR	3
#define M_SP	4
#define M_SR	5
#define M_PC	6
#define M_IMM	7
#define M_ZERO	8
#define M_ZERX	9
#define M_ZERY	10
#define M_ABS	11
#define M_ABSX	12
#define M_ABSY	13
#define M_AIND	14
#define M_INDX	15
#define M_INDY	16
#define M_REL	17
#define M_FC	18
#define M_FD	19
#define M_FI	20
#define M_FV	21
#define M_ADDR	22
#define M_	23

#define M_ACIM	24	/* Source: AC & IMMED (bus collision) */
#define M_ANXR	25	/* Source: AC & XR (bus collision) */
#define M_AXIM	26	/* Source: (AC | #EE) & XR & IMMED (bus collision) */
#define M_ACNC	27	/* Dest: M_AC and Carry = Negative */
#define M_ACXR	28	/* Dest: M_AC, M_XR */

#define M_SABY	29	/* Source: (ABS_Y & SP) (bus collision) */
#define M_ACXS	30	/* Dest: M_AC, M_XR, M_SP */
#define M_STH0	31	/* Dest: Store (src & Addr_Hi+1) to (Addr +0x100) */
#define M_STH1	32
#define M_STH2	33
#define M_STH3	34

#define IMPLIED		0
#define ACCUMULATOR	1
#define IMMEDIATE	2

#define ZERO_PAGE	3
#define ZERO_PAGE_X	4
#define ZERO_PAGE_Y	5

#define ABSOLUTE	6
#define ABSOLUTE_X	7
#define ABSOLUTE_Y	8

#define ABS_INDIRECT	9
#define INDIRECT_X	10
#define INDIRECT_Y	11

#define RELATIVE	12

#define ASS_CODE	13

int     clength[] = {1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 2, 2, 2, 0};

struct lookup_tag lookup[] = {

	/****  Positive  ****/

	/* 00 */ {	"BRK",	IMPLIED, M_NONE, M_PC, 7, 0},	/* Pseudo Absolute */
	/* 01 */ {	"ORA",	INDIRECT_X, M_INDX, M_AC, 6, 0},	/* (Indirect,X) */
    /* 02 */ {  ".JAM",  IMPLIED, M_NONE, M_NONE, 0, 0}, /* TILT */
    /* 03 */ {  ".SLO",  INDIRECT_X, M_INDX, M_INDX, 8, 0},

    /* 04 */ {  ".NOOP", ZERO_PAGE, M_NONE, M_NONE, 3, 0},
	/* 05 */ {	"ORA",	ZERO_PAGE, M_ZERO, M_AC, 3, 0},	/* Zeropage */
	/* 06 */ {	"ASL",	ZERO_PAGE, M_ZERO, M_ZERO, 5, 0},	/* Zeropage */
    /* 07 */ {  ".SLO",  ZERO_PAGE, M_ZERO, M_ZERO, 5, 0},

	/* 08 */ {	"PHP",	IMPLIED, M_SR, M_NONE, 3, 0},
	/* 09 */ {	"ORA",	IMMEDIATE, M_IMM, M_AC, 2, 0},	/* Immediate */
	/* 0a */ {	"ASL",	ACCUMULATOR, M_AC, M_AC, 2, 0},	/* Accumulator */
    /* 0b */ {  ".ANC",  IMMEDIATE, M_ACIM, M_ACNC, 2, 0},

    /* 0c */ {  ".NOOP", ABSOLUTE, M_NONE, M_NONE, 4, 0},
	/* 0d */ {	"ORA",	ABSOLUTE, M_ABS, M_AC, 4, 0},	/* Absolute */
	/* 0e */ {	"ASL",	ABSOLUTE, M_ABS, M_ABS, 6, 0},	/* Absolute */
    /* 0f */ {  ".SLO",  ABSOLUTE, M_ABS, M_ABS, 6, 0},

	/* 10 */ {	"BPL",	RELATIVE, M_REL, M_NONE, 2, 0},
	/* 11 */ {	"ORA",	INDIRECT_Y, M_INDY, M_AC, 5, 1}, /* (Indirect),Y */
    /* 12 */ {  ".JAM",  IMPLIED, M_NONE, M_NONE, 0, 0}, /* TILT */
    /* 13 */ {  ".SLO",  INDIRECT_Y, M_INDY, M_INDY, 8, 0},

    /* 14 */ {  ".NOOP", ZERO_PAGE_X, M_NONE, M_NONE, 4, 0},
	/* 15 */ {	"ORA",	ZERO_PAGE_X, M_ZERX, M_AC, 4, 0},	/* Zeropage,X */
	/* 16 */ {	"ASL",	ZERO_PAGE_X, M_ZERX, M_ZERX, 6, 0},/* Zeropage,X */
    /* 17 */ {  ".SLO",  ZERO_PAGE_X, M_ZERX, M_ZERX, 6, 0},

	/* 18 */ {	"CLC",	IMPLIED, M_NONE, M_FC, 2, 0},
	/* 19 */ {	"ORA",	ABSOLUTE_Y, M_ABSY, M_AC, 4, 1},	/* Absolute,Y */
    /* 1a */ {  ".NOOP", IMPLIED, M_NONE, M_NONE, 2, 0},
    /* 1b */ {  ".SLO",  ABSOLUTE_Y, M_ABSY, M_ABSY, 7, 0},

    /* 1c */ {  ".NOOP", ABSOLUTE_X, M_NONE, M_NONE, 4, 1},
	/* 1d */ {	"ORA",	ABSOLUTE_X, M_ABSX, M_AC,   4, 1},	/* Absolute,X */
	/* 1e */ {	"ASL",	ABSOLUTE_X, M_ABSX, M_ABSX, 7, 0},	/* Absolute,X */
    /* 1f */ {  ".SLO",  ABSOLUTE_X, M_ABSX, M_ABSX, 7, 0},

	/* 20 */ {	"JSR",	ABSOLUTE, M_ADDR, M_PC, 6, 0},
	/* 21 */ {	"AND",	INDIRECT_X, M_INDX, M_AC, 6, 0},	/* (Indirect ,X) */
    /* 22 */ {  ".JAM",  IMPLIED, M_NONE, M_NONE,    0, 0},  /* TILT */
    /* 23 */ {  ".RLA",  INDIRECT_X, M_INDX, M_INDX, 8, 0},

	/* 24 */ {	"BIT",	ZERO_PAGE, M_ZERO, M_NONE, 3, 0},	/* Zeropage */
	/* 25 */ {	"AND",	ZERO_PAGE, M_ZERO, M_AC,   3, 0},	/* Zeropage */
	/* 26 */ {	"ROL",	ZERO_PAGE, M_ZERO, M_ZERO, 5, 0},	/* Zeropage */
    /* 27 */ {  ".RLA",  ZERO_PAGE, M_ZERO, M_ZERO, 5, 0},

	/* 28 */ {	"PLP",	IMPLIED, M_NONE, M_SR, 4, 0},
	/* 29 */ {	"AND",	IMMEDIATE, M_IMM, M_AC, 2, 0},	/* Immediate */
	/* 2a */ {	"ROL",	ACCUMULATOR, M_AC, M_AC, 2, 0},	/* Accumulator */
    /* 2b */ {  ".ANC",  IMMEDIATE, M_ACIM, M_ACNC, 2, 0},

	/* 2c */ {	"BIT",	ABSOLUTE, M_ABS, M_NONE, 4, 0},	/* Absolute */
	/* 2d */ {	"AND",	ABSOLUTE, M_ABS, M_AC,  4, 0},	/* Absolute */
	/* 2e */ {	"ROL",	ABSOLUTE, M_ABS, M_ABS, 6, 0},	/* Absolute */
    /* 2f */ {  ".RLA",  ABSOLUTE, M_ABS, M_ABS, 6, 0},

	/* 30 */ {	"BMI",	RELATIVE, M_REL, M_NONE, 2, 0},
	/* 31 */ {	"AND",	INDIRECT_Y, M_INDY, M_AC, 5, 1},	/* (Indirect),Y */
    /* 32 */ {  ".JAM",  IMPLIED, M_NONE, M_NONE, 0, 0}, /* TILT */
    /* 33 */ {  ".RLA",  INDIRECT_Y, M_INDY, M_INDY, 8, 0},

    /* 34 */ {  ".NOOP", ZERO_PAGE_X, M_NONE, M_NONE, 4, 0},
	/* 35 */ {	"AND",	ZERO_PAGE_X, M_ZERX, M_AC,   4, 0},	/* Zeropage,X */
    /* 36 */ {  "ROL",  ZERO_PAGE_X, M_ZERX, M_ZERX, 6, 0},/* Zeropage,X */
    /* 37 */ {  ".RLA",  ZERO_PAGE_X, M_ZERX, M_ZERX, 6, 0},

	/* 38 */ {	"SEC",	IMPLIED, M_NONE, M_FC, 2, 0},
	/* 39 */ {	"AND",	ABSOLUTE_Y, M_ABSY, M_AC, 4, 1},	/* Absolute,Y */
    /* 3a */ {  ".NOOP", IMPLIED, M_NONE, M_NONE,  2, 0},
    /* 3b */ {  ".RLA",  ABSOLUTE_Y, M_ABSY, M_ABSY, 7, 0},

    /* 3c */ {  ".NOOP", ABSOLUTE_X, M_NONE, M_NONE, 4, 1},
	/* 3d */ {	"AND",	ABSOLUTE_X, M_ABSX, M_AC,   4, 1},	/* Absolute,X */
    /* 3e */ {  "ROL",  ABSOLUTE_X, M_ABSX, M_ABSX, 7, 0}, /* Absolute,X */
    /* 3f */ {  ".RLA",  ABSOLUTE_X, M_ABSX, M_ABSX, 7, 0},

	/* 40 */ {	"RTI" ,	IMPLIED, M_NONE, M_PC, 6, 0},
	/* 41 */ {	"EOR",	INDIRECT_X, M_INDX, M_AC, 6, 0},	/* (Indirect,X) */
    /* 42 */ {  ".JAM",  IMPLIED, M_NONE, M_NONE, 0, 0}, /* TILT */
    /* 43 */ {  ".SRE",  INDIRECT_X, M_INDX, M_INDX, 8, 0},

    /* 44 */ {  ".NOOP", ZERO_PAGE, M_NONE, M_NONE, 3, 0},
	/* 45 */ {	"EOR",	ZERO_PAGE, M_ZERO, M_AC,   3, 0},	/* Zeropage */
	/* 46 */ {	"LSR",	ZERO_PAGE, M_ZERO, M_ZERO, 5, 0},	/* Zeropage */
    /* 47 */ {  ".SRE",  ZERO_PAGE, M_ZERO, M_ZERO, 5, 0},

	/* 48 */ {	"PHA",	IMPLIED, M_AC, M_NONE,   3, 0},
	/* 49 */ {	"EOR",	IMMEDIATE, M_IMM, M_AC,  2, 0},	/* Immediate */
	/* 4a */ {	"LSR",	ACCUMULATOR, M_AC, M_AC, 2, 0},	/* Accumulator */
    /* 4b */ {  ".ASR",  IMMEDIATE, M_ACIM, M_AC, 2, 0}, /* (AC & IMM) >>1 */

	/* 4c */ {	"JMP",	ABSOLUTE, M_ADDR, M_PC, 3, 0},	/* Absolute */
	/* 4d */ {	"EOR",	ABSOLUTE, M_ABS, M_AC,  4, 0},	/* Absolute */
	/* 4e */ {	"LSR",	ABSOLUTE, M_ABS, M_ABS, 6, 0},	/* Absolute */
    /* 4f */ {  ".SRE",  ABSOLUTE, M_ABS, M_ABS, 6, 0},

	/* 50 */ {	"BVC",	RELATIVE, M_REL, M_NONE,  2, 0},
	/* 51 */ {	"EOR",	INDIRECT_Y, M_INDY, M_AC, 5, 1}, /* (Indirect),Y */
    /* 52 */ {  ".JAM",  IMPLIED, M_NONE, M_NONE,  0, 0},    /* TILT */
    /* 53 */ {  ".SRE",  INDIRECT_Y, M_INDY, M_INDY, 8, 0},

    /* 54 */ {  ".NOOP", ZERO_PAGE_X, M_NONE, M_NONE, 4, 0},
	/* 55 */ {	"EOR",	ZERO_PAGE_X, M_ZERX, M_AC,   4, 0},	/* Zeropage,X */
	/* 56 */ {	"LSR",	ZERO_PAGE_X, M_ZERX, M_ZERX, 6, 0},/* Zeropage,X */
    /* 57 */ {  ".SRE",  ZERO_PAGE_X, M_ZERX, M_ZERX, 6, 0},

	/* 58 */ {	"CLI",	IMPLIED, M_NONE, M_FI,     2, 0},
	/* 59 */ {	"EOR",	ABSOLUTE_Y, M_ABSY, M_AC,  4, 1},	/* Absolute,Y */
    /* 5a */ {  ".NOOP", IMPLIED, M_NONE, M_NONE,   2, 0},
    /* 5b */ {  ".SRE",  ABSOLUTE_Y, M_ABSY, M_ABSY, 7, 0},

    /* 5c */ {  ".NOOP", ABSOLUTE_X, M_NONE, M_NONE, 4, 1},
	/* 5d */ {	"EOR",	ABSOLUTE_X, M_ABSX, M_AC,   4, 1},	/* Absolute,X */
	/* 5e */ {	"LSR",	ABSOLUTE_X, M_ABSX, M_ABSX, 7, 0},	/* Absolute,X */
    /* 5f */ {  ".SRE",  ABSOLUTE_X, M_ABSX, M_ABSX, 7, 0},

	/* 60 */ {	"RTS",	IMPLIED, M_NONE, M_PC, 6, 0},
	/* 61 */ {	"ADC",	INDIRECT_X, M_INDX, M_AC, 6, 0},	/* (Indirect,X) */
    /* 62 */ {  ".JAM",  IMPLIED, M_NONE, M_NONE, 0, 0}, /* TILT */
    /* 63 */ {  ".RRA",  INDIRECT_X, M_INDX, M_INDX, 8, 0},

    /* 64 */ {  ".NOOP", ZERO_PAGE, M_NONE, M_NONE, 3, 0},
	/* 65 */ {	"ADC",	ZERO_PAGE, M_ZERO, M_AC,   3, 0},	/* Zeropage */
	/* 66 */ {	"ROR",	ZERO_PAGE, M_ZERO, M_ZERO, 5, 0},	/* Zeropage */
    /* 67 */ {  ".RRA",  ZERO_PAGE, M_ZERO, M_ZERO, 5, 0},

	/* 68 */ {	"PLA",	IMPLIED, M_NONE, M_AC,   4, 0},
	/* 69 */ {	"ADC",	IMMEDIATE, M_IMM, M_AC,  2, 0},	/* Immediate */
	/* 6a */ {	"ROR",	ACCUMULATOR, M_AC, M_AC, 2, 0},	/* Accumulator */
    /* 6b */ {  ".ARR",  IMMEDIATE, M_ACIM, M_AC, 2, 0}, /* ARR isn't typo */

	/* 6c */ {	"JMP",	ABS_INDIRECT, M_AIND, M_PC,  5, 0},	/* Indirect */
	/* 6d */ {	"ADC",	ABSOLUTE, M_ABS, M_AC,  4, 0},	/* Absolute */
	/* 6e */ {	"ROR",	ABSOLUTE, M_ABS, M_ABS, 6, 0},	/* Absolute */
    /* 6f */ {  ".RRA",  ABSOLUTE, M_ABS, M_ABS, 6, 0},

	/* 70 */ {	"BVS",	RELATIVE, M_REL, M_NONE,  2, 0},
	/* 71 */ {	"ADC",	INDIRECT_Y, M_INDY, M_AC, 5, 1}, /* (Indirect),Y */
    /* 72 */ {  ".JAM",  IMPLIED, M_NONE, M_NONE,  0, 0}, /* TILT relative? */
    /* 73 */ {  ".RRA",  INDIRECT_Y, M_INDY, M_INDY, 8, 0},

    /* 74 */ {  ".NOOP", ZERO_PAGE_X, M_NONE, M_NONE, 4, 0},
	/* 75 */ {	"ADC",	ZERO_PAGE_X, M_ZERX, M_AC,   4, 0}, /* Zeropage,X */
	/* 76 */ {	"ROR",	ZERO_PAGE_X, M_ZERX, M_ZERX, 6, 0}, /* Zeropage,X */
    /* 77 */ {  ".RRA",  ZERO_PAGE_X, M_ZERX, M_ZERX, 6, 0},

	/* 78 */ {	"SEI",	IMPLIED, M_NONE, M_FI, 2, 0},
	/* 79 */ {	"ADC",	ABSOLUTE_Y, M_ABSY, M_AC, 4, 1},	/* Absolute,Y */
    /* 7a */ {  ".NOOP", IMPLIED, M_NONE, M_NONE,  2, 0},
    /* 7b */ {  ".RRA",  ABSOLUTE_Y, M_ABSY, M_ABSY, 7, 0},

    /* 7c */ {  ".NOOP", ABSOLUTE_X, M_NONE, M_NONE, 4, 1},
	/* 7d */ {	"ADC",	ABSOLUTE_X, M_ABSX, M_AC,   4, 1},	/* Absolute,X */
    /* 7e */ {  "ROR",  ABSOLUTE_X, M_ABSX, M_ABSX, 7, 0},  /* Absolute,X */
    /* 7f */ {  ".RRA",  ABSOLUTE_X, M_ABSX, M_ABSX, 7, 0},

	/****  Negative  ****/

    /* 80 */ {  ".NOOP", IMMEDIATE, M_NONE, M_NONE, 2, 0},
	/* 81 */ {	"STA",	INDIRECT_X, M_AC, M_INDX,  6, 0},	/* (Indirect,X) */
    /* 82 */ {  ".NOOP", IMMEDIATE, M_NONE, M_NONE,  2, 0},
    /* 83 */ {  ".SAX",  INDIRECT_X, M_ANXR, M_INDX, 6, 0},

	/* 84 */ {	"STY",	ZERO_PAGE, M_YR, M_ZERO,  3, 0},	/* Zeropage */
	/* 85 */ {	"STA",	ZERO_PAGE, M_AC, M_ZERO,  3, 0},	/* Zeropage */
	/* 86 */ {	"STX",	ZERO_PAGE, M_XR, M_ZERO,  3, 0},	/* Zeropage */
    /* 87 */ {  ".SAX",  ZERO_PAGE, M_ANXR, M_ZERO, 3, 0},

	/* 88 */ {	"DEY",	IMPLIED, M_YR, M_YR, 2, 0},
    /* 89 */ {  ".NOOP", IMMEDIATE, M_NONE, M_NONE, 2, 0},
	/* 8a */ {	"TXA",	IMPLIED, M_XR, M_AC, 2, 0},
	/****  very abnormal: usually AC = AC | #$EE & XR & #$oper  ****/
    /* 8b */ {  ".ANE",  IMMEDIATE, M_AXIM, M_AC, 2, 0},

	/* 8c */ {	"STY",	ABSOLUTE, M_YR, M_ABS, 4, 0},	/* Absolute */
	/* 8d */ {	"STA",	ABSOLUTE, M_AC, M_ABS, 4, 0},	/* Absolute */
	/* 8e */ {	"STX",	ABSOLUTE, M_XR, M_ABS, 4, 0},	/* Absolute */
    /* 8f */ {  ".SAX",  ABSOLUTE, M_ANXR, M_ABS, 4, 0},

	/* 90 */ {	"BCC",	RELATIVE, M_REL, M_NONE, 2, 0},
	/* 91 */ {	"STA",	INDIRECT_Y, M_AC, M_INDY, 6, 0},	/* (Indirect),Y */
    /* 92 */ {  ".JAM",  IMPLIED, M_NONE, M_NONE, 0, 0}, /* TILT relative? */
    /* 93 */ {  ".SHA",  INDIRECT_Y, M_ANXR, M_STH0, 6, 0},

	/* 94 */ {	"STY",	ZERO_PAGE_X, M_YR, M_ZERX, 4, 0},	/* Zeropage,X */
	/* 95 */ {	"STA",	ZERO_PAGE_X, M_AC, M_ZERX, 4, 0},	/* Zeropage,X */
	/* 96 */ {	"STX",	ZERO_PAGE_Y, M_XR, M_ZERY, 4, 0},	/* Zeropage,Y */
    /* 97 */ {  ".SAX",  ZERO_PAGE_Y, M_ANXR, M_ZERY, 4, 0},

	/* 98 */ {	"TYA",	IMPLIED, M_YR, M_AC, 2, 0},
	/* 99 */ {	"STA",	ABSOLUTE_Y, M_AC, M_ABSY, 5, 0},	/* Absolute,Y */
	/* 9a */ {	"TXS",	IMPLIED, M_XR, M_SP, 2, 0},
	/*** This is very mysterious comm AND ... */
    /* 9b */ {  ".SHS",  ABSOLUTE_Y, M_ANXR, M_STH3, 5, 0},

    /* 9c */ {  ".SHY",  ABSOLUTE_X, M_YR, M_STH2, 5, 0},
	/* 9d */ {	"STA",	ABSOLUTE_X, M_AC, M_ABSX, 5, 0},	/* Absolute,X */
    /* 9e */ {  ".SHX",  ABSOLUTE_Y, M_XR, M_STH1, 5, 0},
    /* 9f */ {  ".SHA",  ABSOLUTE_Y, M_ANXR, M_STH1, 5, 0},

	/* a0 */ {	"LDY",	IMMEDIATE, M_IMM, M_YR, 2, 0},	/* Immediate */
	/* a1 */ {	"LDA",	INDIRECT_X, M_INDX, M_AC, 6, 0},	/* (indirect,X) */
	/* a2 */ {	"LDX",	IMMEDIATE, M_IMM, M_XR, 2, 0},	/* Immediate */
    /* a3 */ {  ".LAX",  INDIRECT_X, M_INDX, M_ACXR, 6, 0},  /* (indirect,X) */

	/* a4 */ {	"LDY",	ZERO_PAGE, M_ZERO, M_YR, 3, 0},	/* Zeropage */
	/* a5 */ {	"LDA",	ZERO_PAGE, M_ZERO, M_AC, 3, 0},	/* Zeropage */
	/* a6 */ {	"LDX",	ZERO_PAGE, M_ZERO, M_XR, 3, 0},	/* Zeropage */
    /* a7 */ {  ".LAX",  ZERO_PAGE, M_ZERO, M_ACXR, 3, 0},

	/* a8 */ {	"TAY",	IMPLIED, M_AC, M_YR,    2, 0},
	/* a9 */ {	"LDA",	IMMEDIATE, M_IMM, M_AC, 2, 0},	/* Immediate */
    /* aa */ {  "TAX",  IMPLIED, M_AC, M_XR,    2, 0},
    /* ab */ {  ".LXA",  IMMEDIATE, M_ACIM, M_ACXR, 2, 0},   /* LXA isn't a typo */

	/* ac */ {	"LDY",	ABSOLUTE, M_ABS, M_YR, 4, 0},	/* Absolute */
	/* ad */ {	"LDA",	ABSOLUTE, M_ABS, M_AC, 4, 0},	/* Absolute */
	/* ae */ {	"LDX",	ABSOLUTE, M_ABS, M_XR, 4, 0},	/* Absolute */
    /* af */ {  ".LAX",  ABSOLUTE, M_ABS, M_ACXR, 4, 0},

	/* b0 */ { 	"BCS",	RELATIVE, M_REL, M_NONE,  2, 0},
	/* b1 */ {	"LDA",	INDIRECT_Y, M_INDY, M_AC, 5, 1}, /* (indirect),Y */
    /* b2 */ {  ".JAM",  IMPLIED, M_NONE, M_NONE,  0, 0}, /* TILT */
    /* b3 */ {  ".LAX",  INDIRECT_Y, M_INDY, M_ACXR, 5, 1},

	/* b4 */ {	"LDY",	ZERO_PAGE_X, M_ZERX, M_YR, 4, 0},	/* Zeropage,X */
	/* b5 */ {	"LDA",	ZERO_PAGE_X, M_ZERX, M_AC, 4, 0},	/* Zeropage,X */
	/* b6 */ {	"LDX",	ZERO_PAGE_Y, M_ZERY, M_XR, 4, 0},	/* Zeropage,Y */
    /* b7 */ {  ".LAX",  ZERO_PAGE_Y, M_ZERY, M_ACXR, 4, 0},

	/* b8 */ {	"CLV",	IMPLIED, M_NONE, M_FV,    2, 0},
	/* b9 */ {	"LDA",	ABSOLUTE_Y, M_ABSY, M_AC, 4, 1},	/* Absolute,Y */
	/* ba */ {	"TSX",	IMPLIED, M_SP, M_XR,      2, 0},
    /* bb */ {  ".LAS",  ABSOLUTE_Y, M_SABY, M_ACXS, 4, 1},

	/* bc */ {	"LDY",	ABSOLUTE_X, M_ABSX, M_YR, 4, 1},	/* Absolute,X */
	/* bd */ {	"LDA",	ABSOLUTE_X, M_ABSX, M_AC, 4, 1},	/* Absolute,X */
	/* be */ {	"LDX",	ABSOLUTE_Y, M_ABSY, M_XR, 4, 1},	/* Absolute,Y */
    /* bf */ {  ".LAX",  ABSOLUTE_Y, M_ABSY, M_ACXR, 4, 1},

	/* c0 */ {	"CPY",	IMMEDIATE, M_IMM, M_NONE, 2, 0},	/* Immediate */
	/* c1 */ {	"CMP",	INDIRECT_X, M_INDX, M_NONE, 6, 0},	/* (Indirect,X) */
    /* c2 */ {  ".NOOP", IMMEDIATE, M_NONE, M_NONE, 2, 0},   /* occasional TILT */
    /* c3 */ {  ".DCP",  INDIRECT_X, M_INDX, M_INDX, 8, 0},

	/* c4 */ {	"CPY",	ZERO_PAGE, M_ZERO, M_NONE, 3, 0},	/* Zeropage */
	/* c5 */ {	"CMP",	ZERO_PAGE, M_ZERO, M_NONE, 3, 0},	/* Zeropage */
	/* c6 */ {	"DEC",	ZERO_PAGE, M_ZERO, M_ZERO, 5, 0},	/* Zeropage */
    /* c7 */ {  ".DCP",  ZERO_PAGE, M_ZERO, M_ZERO, 5, 0},

	/* c8 */ {	"INY",	IMPLIED, M_YR, M_YR, 2, 0},
	/* c9 */ {	"CMP",	IMMEDIATE, M_IMM, M_NONE, 2, 0},	/* Immediate */
	/* ca */ {	"DEX",	IMPLIED, M_XR, M_XR, 2, 0},
    /* cb */ {  ".SBX",  IMMEDIATE, M_IMM, M_XR, 2, 0},

	/* cc */ {	"CPY",	ABSOLUTE, M_ABS, M_NONE, 4, 0},	/* Absolute */
	/* cd */ {	"CMP",	ABSOLUTE, M_ABS, M_NONE, 4, 0},	/* Absolute */
	/* ce */ {	"DEC",	ABSOLUTE, M_ABS, M_ABS,  6, 0},	/* Absolute */
    /* cf */ {  ".DCP",  ABSOLUTE, M_ABS, M_ABS,  6, 0},

	/* d0 */ {	"BNE",	RELATIVE, M_REL, M_NONE, 2, 0},
	/* d1 */ {	"CMP",	INDIRECT_Y, M_INDY, M_NONE, 5, 1},	/* (Indirect),Y */
    /* d2 */ {  ".JAM",  IMPLIED, M_NONE, M_NONE,    0, 0},  /* TILT */
    /* d3 */ {  ".DCP",  INDIRECT_Y, M_INDY, M_INDY, 8, 0},

    /* d4 */ {  ".NOOP", ZERO_PAGE_X, M_NONE, M_NONE, 4, 0},
	/* d5 */ {	"CMP",	ZERO_PAGE_X, M_ZERX, M_NONE, 4, 0},/* Zeropage,X */
	/* d6 */ {	"DEC",	ZERO_PAGE_X, M_ZERX, M_ZERX, 6, 0},/* Zeropage,X */
    /* d7 */ {  ".DCP",  ZERO_PAGE_X, M_ZERX, M_ZERX, 6, 0},

	/* d8 */ {	"CLD",	IMPLIED, M_NONE, M_FD, 2, 0},
	/* d9 */ {	"CMP",	ABSOLUTE_Y, M_ABSY, M_NONE, 4, 1},	/* Absolute,Y */
    /* da */ {  ".NOOP", IMPLIED, M_NONE, M_NONE,    2, 0},
    /* db */ {  ".DCP",  ABSOLUTE_Y, M_ABSY, M_ABSY, 7, 0},

    /* dc */ {  ".NOOP", ABSOLUTE_X, M_NONE, M_NONE, 4, 1},
	/* dd */ {	"CMP",	ABSOLUTE_X, M_ABSX, M_NONE, 4, 1},	/* Absolute,X */
	/* de */ {	"DEC",	ABSOLUTE_X, M_ABSX, M_ABSX, 7, 0},	/* Absolute,X */
    /* df */ {  ".DCP",  ABSOLUTE_X, M_ABSX, M_ABSX, 7, 0},

	/* e0 */ {	"CPX",	IMMEDIATE, M_IMM, M_NONE, 2, 0},	/* Immediate */
	/* e1 */ {	"SBC",	INDIRECT_X, M_INDX, M_AC, 6, 0},	/* (Indirect,X) */
    /* e2 */ {  ".NOOP", IMMEDIATE, M_NONE, M_NONE,  2, 0},
    /* e3 */ {  ".ISB",  INDIRECT_X, M_INDX, M_INDX, 8, 0},

	/* e4 */ {	"CPX",	ZERO_PAGE, M_ZERO, M_NONE, 3, 0},	/* Zeropage */
	/* e5 */ {	"SBC",	ZERO_PAGE, M_ZERO, M_AC,   3, 0},	/* Zeropage */
	/* e6 */ {	"INC",	ZERO_PAGE, M_ZERO, M_ZERO, 5, 0},	/* Zeropage */
    /* e7 */ {  ".ISB",  ZERO_PAGE, M_ZERO, M_ZERO, 5, 0},

	/* e8 */ {	"INX",	IMPLIED, M_XR, M_XR,     2, 0},
	/* e9 */ {	"SBC",	IMMEDIATE, M_IMM, M_AC,  2, 0},	/* Immediate */
	/* ea */ {	"NOP",	IMPLIED, M_NONE, M_NONE, 2, 0},
    /* eb */ {  ".USBC", IMMEDIATE, M_IMM, M_AC,  2, 0}, /* same as e9 */

	/* ec */ {	"CPX",	ABSOLUTE, M_ABS, M_NONE, 4, 0},	/* Absolute */
	/* ed */ {	"SBC",	ABSOLUTE, M_ABS, M_AC,  4, 0},	/* Absolute */
	/* ee */ {	"INC",	ABSOLUTE, M_ABS, M_ABS, 6, 0},	/* Absolute */
    /* ef */ {  ".ISB",  ABSOLUTE, M_ABS, M_ABS, 6, 0},

	/* f0 */ {	"BEQ",	RELATIVE, M_REL, M_NONE,  2, 0},
	/* f1 */ {	"SBC",	INDIRECT_Y, M_INDY, M_AC, 5, 1}, /* (Indirect),Y */
    /* f2 */ {  ".JAM",  IMPLIED, M_NONE, M_NONE,  0, 0}, /* TILT */
    /* f3 */ {  ".ISB",  INDIRECT_Y, M_INDY, M_INDY, 8, 0},

    /* f4 */ {  ".NOOP", ZERO_PAGE_X, M_NONE, M_NONE, 4, 0},
	/* f5 */ {	"SBC",	ZERO_PAGE_X, M_ZERX, M_AC,   4, 0}, /* Zeropage,X */
	/* f6 */ {	"INC",	ZERO_PAGE_X, M_ZERX, M_ZERX, 6, 0}, /* Zeropage,X */
    /* f7 */ {  ".ISB",  ZERO_PAGE_X, M_ZERX, M_ZERX, 6, 0},

	/* f8 */ {	"SED",	IMPLIED, M_NONE, M_FD,    2, 0},
	/* f9 */ {	"SBC",	ABSOLUTE_Y, M_ABSY, M_AC, 4, 1}, /* Absolute,Y */
    /* fa */ {  ".NOOP", IMPLIED, M_NONE, M_NONE,  2, 0},
    /* fb */ {  ".ISB",  ABSOLUTE_Y, M_ABSY, M_ABSY, 7, 0},

    /* fc */ {  ".NOOP", ABSOLUTE_X, M_NONE, M_NONE, 4, 1},
	/* fd */ {	"SBC",	ABSOLUTE_X, M_ABSX, M_AC,   4, 1},	/* Absolute,X */
    /* fe */ {  "INC",  ABSOLUTE_X, M_ABSX, M_ABSX, 7, 0},  /* Absolute,X */
    /* ff */ {  ".ISB",  ABSOLUTE_X, M_ABSX, M_ABSX, 7, 0}
};

/* structure to hold list of addresses */

struct qnode {
    unsigned int address;
	struct qnode *next;
};

struct qnode *addq(struct qnode *, unsigned int);
struct qnode *delq(struct qnode *);
void qprint(struct qnode *);

/* allocates enough memory to store 1 q node */

struct qnode *qalloc(void) {
        return (struct qnode *) malloc(sizeof(struct qnode));
}

/* returns pointer to duplicate of s */

struct qnode *qdup(struct qnode *s)
{
        struct qnode *temp, *p;
        p = NULL;
        temp = s;
        while (temp != NULL) {
                p = addq(p,temp->address);
                temp = temp->next;
        }
        return p;
}

/* adds q node to tail of p - use form 'p = addq(p,w,t)' */

struct qnode *addq(struct qnode *p, unsigned int address)
{
     
        if (p == NULL) {
                p = qalloc();
		if (p==NULL)
                {
                    fprintf (stderr, "out of memory for enqueue operation");
                }
                p->address = address;
                p->next = NULL;
        }
        else
          p->next = addq(p->next, address);
        return p;
        
}

/* remove node from head of p - use form 'p = delq(p)' */
/* frees memory previously used by node deleted            */

struct qnode *delq(struct qnode *p)
{
        struct qnode *t;
        
        t = p;
        
        if (p != NULL) {
          t = p->next;
          free(p);
        }
        
        return t;
} 

/* deletes all nodes from queue pointed to by p */

void clearq(struct qnode *p)
{
        while (p != NULL)
                p = delq(p);
}
        
/* prints all bursts in a q - used for debugging */

void qprint(struct qnode *p)
{
        if (p != NULL) {
                fprintf(stderr,"Address: %0.4X\n",p->address);
                qprint(p->next);
        }
}

void main(int argc,char *argv[])
{
    int c,i,j;
    char file[50],config[50], parms[132];
    char oflag;
    time_t currtime;

    app_data.start=0x0;
    app_data.load=0x0000;
    app_data.length=0;
    app_data.end=0x0FFF;
    app_data.disp_data=0;
    addressq = NULL;
    intflag = 0;

    strcpy(file,"");

    /* Flag defaults */
    aflag = 1;
    bflag = 0;
    cflag = 0;
    fflag = 0;
    kflag = 0;
    pflag = 0;
    sflag = 0;
    rflag = 0;
    dflag = 1;
    a78flag = 0;

    hdr_exists = NO_HEADER;	/* until we open the file, we don't know if it has an a78 header */

    strcpy(orgmnc,"   ORG ");
    strcpy(parms,"");
    for (i=0;i<argc;i++) {
        strcat(parms,argv[i]);
        strcat(parms," ");
    }

    while (--argc > 1 && (*++argv)[0] == '-')
        while (c = *++argv[0])
            switch(c) {
            case 'a':
                aflag = 0;
                break;
            case 'c':
                cflag = 1;
                i=0;
                while (*++argv[0] != '\0')
                    config[i++] = *argv[0];
                config[i]=*argv[0]--;
                fprintf(stderr,"Using %s config file\n",config);
                break;
            case 'd':
                dflag = 0;
                break;
            case 'o':
                oflag = *++argv[0];
                switch (oflag) {
                case '1':
                    strcpy(orgmnc,"   ORG ");
                    break;
                case '2':
                    strcpy(orgmnc,"   *=");
                    break;
                case '3':
                    strcpy(orgmnc,"   .OR ");
                    break;
                default:
                    fprintf(stderr,"Illegal org type %c\n",oflag);
                    break;
                }
                break;
            case 'p':
                pflag = 1;
                break;
            case 's':
                sflag = 1;
                break;
            case 'i':
                intflag = 1;
                break;
            case 'r':
                rflag = 1;
                break;
            case 'f':
                fflag = 1;
                break;
            case '7':
		a78flag = 1;
		break;
            case 'b':
                bflag = 1;
                break;
            case 'k':
                kflag = 1;
                break;
            default:
                fprintf(stderr,"DiStella: illegal option %c\n",c);
                exit(1);
            }
    strcpy(file,*++argv);

    if (argc != 1) {
        fprintf(stderr,"DiStella v3.00 - February 8, 2003\n");
        fprintf(stderr,"\nUse: DiStella [options] file\n");
        fprintf(stderr," options:\n");
        fprintf(stderr,"   -7  Use Atari 7800 MARIA equates and file sizes\n");
        fprintf(stderr,"   -a  Turns 'A' off in accumulator instructions\n");
        fprintf(stderr,"   -c  Defines optional config file to use.  (e.g. -cpacman.cfg)\n");
        fprintf(stderr,"         (see distella.txt for additional information)\n");
        fprintf(stderr,"   -d  Disables automatic code determination\n");
        fprintf(stderr,"   -f  Forces correct address length\n");
        fprintf(stderr,"   -i  Process DMA interrupt Vector (7800 mode)\n");
        fprintf(stderr,"       If 2600 mode, enables -b option\n");
        fprintf(stderr,"   -b  Process BRK interrupt Vector (2600 and 7800 mode)\n");
        fprintf(stderr,"   -k  Enable POKEY equates (7800 mode only, auto-detected if a78 file)\n");
        fprintf(stderr,"   -o# ORG variation: # = 1- ORG $XXXX  2- *=$XXXX  3- .OR $XXXX\n");
        fprintf(stderr,"   -p  Insert psuedo-mnemonic 'processor 6502'\n");
        fprintf(stderr,"   -r  Relocate calls out of address range\n");
        fprintf(stderr,"   -s  Cycle count\n");
        fprintf(stderr,"\n Example: DiStella -pafs pacman.bin > pacman.s\n");
        fprintf(stderr," Example: DiStella -paf7ikscball.cfg ballblaz.bin > ballblaz.asm\n");
        fprintf(stderr,"\n Email: rcolbert@novia.net or dboris@comcast.net\n");
        fprintf(stderr,"          Version 3.0 updates, email jkharvey@voyager.net");
        exit(0);
    }

    if (!file_load(file)) {
        fprintf(stderr,"Unable to load %s\n",file);
        exit(0);
    }
    
    /*====================================*/
    /* Allocate memory for "labels" variable */
    labels=(BYTE *)malloc(app_data.length);
    if (labels == NULL)
    {
       fprintf (stderr, "Malloc failed for 'labels' variable\n");
       exit(1);
    }
    memset(labels,0,app_data.length);
    /*====================================*/


    /*-----------------------------------------------------
       The last 3 words of a program are as follows:

	.word	INTERRUPT   (isr_adr)
	.word	START       (start_adr)
	.word	BRKroutine  (brk_adr)

       Since we always process START, move the Program
         Counter 3 bytes back from the final byte.
     -----------------------------------------------------*/

    pc=app_data.end-3;

    start_adr=read_adr();

    if (app_data.end == 0x7ff) /* 2K case */
    {
        /*============================================
           What is the offset?  Well, it's an address
           where the code segment starts.  For a 2K game,
           it is usually 0xf800, which would then have the
           code data end at 0xffff, but that is not
           necessarily the case.  Because the Atari 2600
           only has 13 address lines, it's possible that
           the "code" can be considered to start in a lot
           of different places.  So, we use the start
           address as a reference to determine where the
           offset is, logically-anded to produce an offset
           that is a multiple of 2K.

           Example:
             Start address = $D973, so therefore
             Offset to code = $D800
             Code range = $D800-$DFFF
         =============================================*/
        offset=(start_adr & 0xf800);
    }
    else if (app_data.end == 0xfff) /* 4K case */
    {
        /*============================================
           The offset is the address where the code segment
           starts.  For a 4K game, it is usually 0xf000,
           which would then have the code data end at 0xffff,
           but that is not necessarily the case.  Because the
           Atari 2600 only has 13 address lines, it's possible
           that the "code" can be considered to start in a lot
           of different places.  So, we use the start
           address as a reference to determine where the
           offset is, logically-anded to produce an offset
           that is a multiple of 4K.

           Example:
             Start address = $D973, so therefore
             Offset to code = $D000
             Code range = $D000-$DFFF
         =============================================*/
        offset=(start_adr - (start_adr % 0x1000));
    }
    else if (app_data.end == 0x1fff) /* 8K case (7800 mode only-- file size is not supported by file_load function) */
        offset=(start_adr & 0xe000);
    else if (app_data.end == 0x3fff) /* 16K case (7800 mode only) */
    {
        /*============================================
           The offset is the address where the code segment starts.
           For a 16K game (it must be Atari 7800 then), it should
           always be at $C000, creating a code range from $C000-
           $CFFF.

           Data outside of this 16K range (i.e. $8000-$BFFF) would
           probably act as a mirror of $C000-$FFFF, therefore acting
           as if it referenced data within the $C000-$FFFF range.
           It is unknown if any 16K 7800 games access
           this mirror, but if so, the mark() function will
           note that the correct address ($C000-$FFFF) is marked
           accordingly.
           For the purposes of this disassembler, references
           to data from $4000-$7FFF for 16K games are ignored.
         =============================================*/
        offset=(start_adr & 0xc000);
    }
    else if (app_data.end == 0x7fff) /* 32K case (7800 mode only) */
    {
        /*============================================
           The offset is the address where the code segment starts.
           For a 32K game (it must be Atari 7800 then), it should
           always be at $C000.

           Example:
             Offset to code = $8000
             Code range = $8000-$FFFF

           Data outside of this 32K range (i.e. $4000-$7FFF) for 32K
           games would either be interpreted as $$8000-$CFFF's data,
           or may even be undefined.
           It is unknown if any 32K 7800 games access
           this mirror, but if so, the mark() function will
           note that the correct address ($8000-$CFFF) is marked
           accordingly.
         =============================================*/
        offset=(0x8000);
    }
    else if (app_data.end == 0xbfff) /* 48K case (7800 mode only) */
    {
        /*=====================================================
          if 48K, the CODE data must ALWAYS start at $4000.
          The CODE range will be $4000-$FFFF, and $0000-$3FFF
          are reserved internal to the 7800 system.
        =====================================================*/
        offset=(0x4000);
        /*-----------------------------------------------------
           if the r flag is on, we don't need it to be,
           because there is nothing to relocate for the 48K
           case-- all addresses are fixed and known.  The
           lower 16K is system, and the upper 48K are code.
        -----------------------------------------------------*/
        rflag = 0;
        /*-----------------------------------------------------
           Likewise, the k flag must be off, since 48K games
           cannot support POKEY hardware.  The POKEY hardware
           would be in 16K segment 2, but that's where some code
           is for a 48K situation.  Since they're mutually
           exclusive, POKEY capability with a 48K game is
           not practical.
        -----------------------------------------------------*/
        kflag = 0;
    }

    if (cflag && !load_config(config)) {
        fprintf(stderr,"Unable to load config file %s\n",config);
        exit(0);
    }

    fprintf(stderr,"PASS 1\n");

    addressq=addq(addressq,start_adr);

    brk_adr=read_adr();
    if (intflag == 1 && a78flag == 0)
    {
        bflag = 1;
    }
    /*--------------------------------------------------------
       If Atari 2600 OR Atari 7800 mode,
         if the "-b" option is on, process BRKroutine
         if the "-b" option is off, don't process BRKroutine
    --------------------------------------------------------*/
    if (bflag)
    {
        addressq=addq(addressq,brk_adr);
        mark(brk_adr,REFERENCED);
    }

    /*--------------------------------------------------------
       If Atari 7800 mode,
         if the "-i" option is on, process ISR routine
         if the "-i" option is off, don't process ISR routine

       To do this, we need to move the Program counter appropriately.
    --------------------------------------------------------*/
    if (intflag == 1 && a78flag == 1)
    {
        pc=app_data.end-5;
        isr_adr=read_adr();
        addressq=addq(addressq,isr_adr);
        mark(isr_adr,REFERENCED);
    }

    if (dflag) {
      while(addressq != NULL) {
          pc=addressq->address;
          pcbeg=pc;
          addressq=delq(addressq);
          disasm(pc,1);
          for (k=pcbeg;k<=pcend;k++)
                  mark(k,REACHABLE);
      }
    
      for (k=0;k<=app_data.end;k=k+1) {
        if (!check_bit(labels[k],REACHABLE))
            mark(k+offset,DATA);
      }
    }

    fprintf(stderr,"PASS 2\n");
    disasm(offset,2);

    time(&currtime);
    printf("; Disassembly of %s\n",file);
    printf("; Disassembled %s",ctime(&currtime));
    printf("; Using DiStella v3.0\n;\n");
    printf("; Command Line: %s\n;\n",parms);
    if (cflag) {
        printf("; %s contents:\n;\n",config);
        while (fgets(parms,79,cfg) != NULL)
            printf(";      %s",parms);
    }
    printf("\n");
    if (pflag)
        printf("      processor 6502\n");

    /* Print list of used equates onto the screen (TIA) if 2600 mode */
    if (a78flag == 0)
    {
	for (i=0;i<=0x3d;i++)
            if (reserved[i] == 1) {
                printf("%s",stella[i]);
                for(j=strlen(stella[i]);j<7;j++)
                    printf(" ");
                printf(" =  $%0.2X\n",i);
            }

        for (i=0x280;i<=0x297;i++)
            if (ioresrvd[i-0x280] == 1) {
                printf("%s",ioregs[i-0x280]);
                for(j=strlen(ioregs[i-0x280]);j<7;j++)
                    printf(" ");
                printf(" =  $%0.4X\n",i);
            }
    }
    else
    {
    /* Print list of used equates onto the screen (MARIA) if 7800 mode */
	for (i=0;i<=0x3f;i++)
            if (reserved[i] == 1) {
                printf("%s",maria[i]);
                for(j=strlen(maria[i]);j<7;j++)
                    printf(" ");
                printf(" =  $%0.2X\n",i);
            }

        for (i=0x280;i<=0x283;i++)
            if (ioresrvd[i-0x280] == 1) {
                printf("%s",mariaio[i-0x280]);
                for(j=strlen(mariaio[i-0x280]);j<7;j++)
                    printf(" ");
                printf(" =  $%0.4X\n",i);
            }

        if (kflag == 1)
        {
            for (i=0x4000;i<=0x400f;i++)
                if (pokresvd[i-0x4000] == 1) {
                    printf("%s",pokey[i-0x4000]);
                    for(j=strlen(pokey[i-0x4000]);j<7;j++)
                        printf(" ");
                    printf(" =  $%0.4X\n",i);
                }
        }

    }

    /* Print Line equates on screen */
    for (i=0;i<=app_data.end;i++)
    {
        if ((labels[i] & (REFERENCED | VALID_ENTRY)) == REFERENCED)
        {
            /* so, if we have a piece of code referenced somewhere else, but cannot locate the label
               in code (i.e because the address is inside of a multi-byte instruction, then we
               print that address on screen for reference */
            printf("L%0.4X   =   ",i+offset);
            printf("$%0.4X\n",i+offset);
        }
    }

    printf("\n");
    printf("    %s",orgmnc);
    printf("$%0.4X\n",offset);

    fprintf(stderr,"PASS 3\n");
    strcpy(linebuff,"");
    strcpy(nextline,"");
    disasm(offset,3);

        free(labels); /* Free dynamic memory before program ends */
	free(mem); /* Free dynamic memory before program ends */
}

unsigned int filesize(FILE *stream)
{
   unsigned int curpos, length;

   curpos = ftell(stream);
   fseek(stream, 0L, SEEK_END);
   length = ftell(stream);
   fseek(stream, curpos, SEEK_SET);
   return length;
}

unsigned int read_adr()
{
	BYTE d1,d2;

	d1=mem[pc++];
	d2=mem[pc++];
	return (unsigned int) ((d2 << 8)+d1);
}

int file_load(char file[50])
{
    FILE *fn;

    char hdr_string[29]; /* Holds "ACTUAL CART DATA STARTS HERE" string for .a78 files */
                         /* 29 = 28 chars + 1 termination byte '\O' */

    int loop_counter; /* For looping through a 7800 header to make sure its valid */

    fn=fopen(file,"rb");

    if (fn == NULL) return 0;

    if (app_data.length == 0)
    {
        app_data.length = filesize(fn);
    }

    if (a78flag == 0)
    {
        if (app_data.length == 2048)
            app_data.end = 0x7ff;
        else if (app_data.length == 4096)
            app_data.end = 0xfff;
        else
        {
            printf("Error: .bin file must be 2048 or 4096 bytes\n");
            printf(" for 2600 games; For 7800 games, .bin file must be\n");
            printf(" 16384, 32768 or 49152 bytes (+128 bytes if header appended)\n");
            printf(" Also, the -7 option must be set or unset appropriately\n");
            exit(1);
        }
    }
    else /* (a78flag == 1) */
    {
	switch (app_data.length)
	{
            /* No 8k 7800 roms exist, so there is no 8K support at this time */
	    /* case 8320:
	        hdr_exists = YES_HEADER;
	    case 8192:
                app_data.end = 0x1fff;
	        break; */
	    case 16512:
	        hdr_exists = YES_HEADER;
	    case 16384:
                app_data.end = 0x3fff;
	        break;
	    case 32896:
	        hdr_exists = YES_HEADER;
	    case 32768:
                app_data.end = 0x7fff;
	        break;
	    case 49280:
	        hdr_exists = YES_HEADER;
	    case 49152:
                app_data.end = 0xbfff;
	        break;
            default:
                printf("Error: .bin file must be 2048 or 4096 bytes\n");
                printf(" for 2600 games; For 7800 games, .bin file must be\n");
                printf(" 16384, 32768 or 49152 bytes (+128 bytes if header appended)\n");
                printf(" Also, the -7 option must be set or unset appropriately\n");
                exit(1);
	        break;
	}
    }

    /*====================================*/
    /* Dynamically allocate memory for "mem" variable */
    mem=(BYTE *)malloc(app_data.length);
    if (mem == NULL)
    {
        printf ("Malloc failed for 'mem' variable\n");
        exit(1);
    }
    memset(mem,0,app_data.length);
    /*====================================*/

    rewind(fn); /* Point to beginning of file again */

    /* If it's got a 7800 header, get some info from it */
    if (hdr_exists == YES_HEADER)
    {
        /*====================================*/
        /* Dynamically allocate memory for 7800 header (if applicable) */
        hdr78=(BYTE *)malloc(128);
        if (hdr78 == NULL)
        {
            printf ("Malloc failed for 'hdr78' variable\n");
            exit(1);
        }
        memset(hdr78,0,128);
        /*====================================*/

        /* read in the 128-byte header */
        fread(&hdr78[app_data.load],1,128,fn);

        strcpy(hdr_string,"ACTUAL CART DATA STARTS HERE");
	
        /* Exit if the header text string does not exist */
        for (loop_counter = 0; loop_counter < 28; loop_counter++)
        {
            if (hdr_string[loop_counter] != hdr78[100+loop_counter])
            {
                printf("a78 file has incorrect header\n");
                exit(1);
            }
        }

        /* Header is correct, so check for POKEY support */
	if (hdr78[54] & 0x01 == 1)
	{
            /* then it's a POKEY cart, so we turn on POKEY equates */
            kflag = 1;
        }
        else
        {
            /* NOT a POKEY cart, so disable POKEY equates */
            kflag = 0;
        }

        /* Everything is set up ok, so we can free the header memory */
	free (hdr78);

	/* read in the rest of the file (i.e. the data) */
        fread(&mem[app_data.load],1,app_data.length-128,fn);
    }
    else /* if no header exists, just read in the file data */
    {
        fread(&mem[app_data.load],1,app_data.length,fn);
    }

    fclose(fn); /* Data is read in, so close the file */

    if (app_data.start == 0)
	app_data.start = app_data.load;

    return 1;
}

int load_config(char *file)
{
    char cfg_line[80];
    char cfg_tok[80];
    unsigned int cfg_beg, cfg_end;

    lineno=0;

    if ((cfg=fopen(file,"r")) == NULL)
        return 0;

    cfg_beg=cfg_end=0;

    while (fgets(cfg_line,79,cfg)!=NULL) {
        strcpy(cfg_tok,"");
        sscanf(cfg_line,"%s %x %x",cfg_tok,&cfg_beg,&cfg_end);
        if (!strcmp(cfg_tok,"DATA")) {
            check_range(cfg_beg,cfg_end);
            for(;cfg_beg<=cfg_end;) {
                mark(cfg_beg,DATA);
                if (cfg_beg == cfg_end)
                    cfg_end = 0;
                else
                    cfg_beg++;
            }
        } else if (!strcmp(cfg_tok,"GFX")) {
            check_range(cfg_beg,cfg_end);
            for(;cfg_beg<=cfg_end;) {
                mark(cfg_beg,GFX);
                if (cfg_beg == cfg_end)
                    cfg_end = 0;
                else
                    cfg_beg++;
            }
        } else if (!strcmp(cfg_tok,"ORG")) {
            offset = cfg_beg;
        } else if (!strcmp(cfg_tok,"CODE")) {
            check_range(cfg_beg,cfg_end);
            for(;cfg_beg<=cfg_end;) {
                mark(cfg_beg,REACHABLE);
                if (cfg_beg == cfg_end)
                    cfg_end = 0;
                else
                    cfg_beg++;
            }
        } else {
            fprintf(stderr,"Invalid line in config file - line ignored\n",lineno);
        }
    }
    rewind(cfg);
    return 1;
}

void check_range(unsigned int beg, unsigned int end)
{
    lineno++;
    if (beg > end) {
        fprintf(stderr,"Beginning of range greater than End in config file in line %d\n",lineno);
        exit(1);
    }

    if (beg > app_data.end + offset) {
        fprintf(stderr,"Beginning of range out of range in line %d\n",lineno);
        exit(1);
    }

    if (beg < offset) {
        fprintf(stderr,"Beginning of range out of range in line %d\n",lineno);
        exit(1);
    }
}

void disasm(unsigned long distart,int pass)
{
    BYTE op;
    BYTE d1,opsrc;
	unsigned long ad;
	short amode;
    int i,bytes,labfound,addbranch;

/*    pc=app_data.start; */
    pc=distart-offset;
	while(pc <= app_data.end) {
        if(pass == 3) {
          if (pc+offset == start_adr)
            printf("\nSTART:\n");
          if ((pc+offset == brk_adr) && (bflag))
            printf("\nBRK_ROUTINE:\n");
          if ((pc+offset == isr_adr) && ((a78flag == 1) && (intflag == 1)))
            printf("\nINTERRUPT_ROUTINE:\n");
        }
        if(check_bit(labels[pc],GFX)) {
/*         && !check_bit(labels[pc],REACHABLE)) { */
            if (pass == 2)
                mark(pc+offset,VALID_ENTRY);
            if (pass == 3) {
                if (check_bit(labels[pc],REFERENCED))
                    printf("L%0.4X: ",pc+offset);
                else
                    printf("       ",pc+offset);
                printf(".byte $%0.2X ; ",mem[pc]);
                showgfx(mem[pc]);
                printf(" $%0.4X\n",pc+offset);
            }
            pc++;
        } else
        if (check_bit(labels[pc],DATA) && !check_bit(labels[pc],GFX)) {
/*            && !check_bit(labels[pc],REACHABLE)) {  */
            mark(pc+offset,VALID_ENTRY);
            if (pass == 3) {
                bytes = 1;
                printf("L%0.4X: .byte ",pc+offset);
                printf("$%0.2X",mem[pc]);
            }
            pc++;

            while (check_bit(labels[pc],DATA) && !check_bit(labels[pc],REFERENCED)
                   && !check_bit(labels[pc],GFX) && pass == 3 && pc <= app_data.end) {
                if (pass == 3) {
                    bytes++;
                    if (bytes == 17) {
                        printf("\n       .byte $%0.2X",mem[pc]);
                        bytes = 1;
                    } else
                        printf(",$%0.2X",mem[pc]);
                }
                pc++;
            }
            if (pass == 3)
                printf("\n");
        } else {
            op=mem[pc];
            /* version 2.1 bug fix */
            if (pass == 2)
                mark(pc+offset,VALID_ENTRY);
            if (pass == 3)
                if (check_bit(labels[pc],REFERENCED)) {
                    printf("L%0.4X: ",pc+offset);
                } else
                    printf("       ");

            amode=lookup[op].addr_mode;
            if (app_data.disp_data) {
                for (i=0; i<clength[amode]; i++) {
                    if (pass == 3)
                        printf("%02X ",mem[pc+i]);
                }
                if (pass == 3)
                    printf("  ");
            }

            pc++;

            if (lookup[op].mnemonic[0] == '.') {
                amode = IMPLIED;
                if (pass == 3) {
                    sprintf(linebuff,".byte $%0.2X ;",op);
                    strcat(nextline,linebuff);
                }
            }

            if (pass == 1) {
                opsrc = lookup[op].source;
                /* M_REL covers BPL, BMI, BVC, BVS, BCC, BCS, BNE, BEQ
                   M_ADDR = JMP $NNNN, JSR $NNNN
                   M_AIND = JMP Abs, Indirect */
                if ((opsrc == M_REL) || (opsrc == M_ADDR) || (opsrc == M_AIND)) {
                    addbranch = 1;
                }
                else
                    addbranch = 0;
            } else if (pass == 3) {
                   sprintf(linebuff,"%s",lookup[op].mnemonic);
                   strcat(nextline,linebuff);
            }

            if (pc >= app_data.end)
            {
                switch(amode)
                {
                    case ABSOLUTE:
                    case ABSOLUTE_X:
                    case ABSOLUTE_Y:
                    case INDIRECT_X:
                    case INDIRECT_Y:
                    case ABS_INDIRECT:
                    {
                        if (pass == 3)
                        {
                            /* Line information is already printed; append .byte since last instruction will
                               put recompilable object larger that original binary file */
                            printf(".byte $%0.2X\n",op);

                            if (pc == app_data.end)
                            {
                                if (check_bit(labels[pc],REFERENCED)) {
                                    printf("L%0.4X: ",pc+offset);
                                } else
                                    printf("       ");
                                op=mem[pc++];
                                printf(".byte $%0.2X\n",op);
                            }
                        }
                        pcend = app_data.end + offset;
                        return;
                    }
                    case ZERO_PAGE:
                    case IMMEDIATE:
                    case ZERO_PAGE_X:
                    case ZERO_PAGE_Y:
                    case RELATIVE:
                    {
                        if (pc > app_data.end)
                        {
                            if (pass == 3)
                            {
                                /* Line information is already printed, but we can remove the
                                   Instruction (i.e. BMI) by simply clearing the buffer to print */
                                strcpy(nextline,"");
                                sprintf(linebuff,".byte $%0.2X",op);
                                strcat(nextline,linebuff);

                                printf("%s",nextline);
                                printf("\n");
                                strcpy(nextline,"");
                            }
                            pc++;
                            pcend = app_data.end + offset;
                            return;
                        }
                    }
                    default:
                        break;
                }
            }

            /* Version 2.1 added the extensions to mnemonics */
            switch(amode) {
/*              case IMPLIED: {
                    if (op == 0x40 || op == 0x60)
                            if (pass == 3) {
                                sprintf(linebuff,"\n");
                                strcat(nextline,linebuff);
                            }
                            break;
                }
*/
                case ACCUMULATOR: {
                     if (pass == 3)
                         if (aflag) {
                             sprintf(linebuff,"    A");
                             strcat(nextline,linebuff);
                         }
                     break;
                }
                case ABSOLUTE: {
                    ad=read_adr();
                    labfound = mark(ad,REFERENCED);
                    if (pass == 1) {
                        if ((addbranch) && !check_bit(labels[ad & app_data.end],REACHABLE)) {
                            if (ad > 0xfff)
                                 addressq=addq(addressq,(ad & app_data.end)+offset);
                            mark(ad,REACHABLE);

                        }
                    } else if (pass == 3) {
                        if (ad < 0x100 && fflag) {
                            sprintf(linebuff,".w  ");
                            strcat(nextline,linebuff);
                        }
                        else {
                            sprintf(linebuff,"    ");
                            strcat(nextline,linebuff);
                        }
                        if (labfound == 1) {
                            sprintf(linebuff,"L%0.4X",ad);
                            strcat(nextline,linebuff);
                        }
                        else if (labfound == 3) {
			    if (a78flag == 0)
                        	sprintf(linebuff,"%s",ioregs[ad-0x280]);
			    else
                        	sprintf(linebuff,"%s",mariaio[ad-0x280]);
                            strcat(nextline,linebuff);
                        }
                        else if (labfound == 5) {
                            sprintf(linebuff,"%s",pokey[ad-0x4000]);
                            strcat(nextline,linebuff);
                        }
                        else if ((labfound == 4) && rflag) {
                            sprintf(linebuff,"L%0.4X",(ad & app_data.end)+offset);
                            strcat(nextline,linebuff);
                        }
                        else {
                            sprintf(linebuff,"$%0.4X",ad);
                            strcat(nextline,linebuff);
                        }
                    }
                    break;
                }
                case ZERO_PAGE: {
                    d1=mem[pc++];
                    labfound = mark(d1,REFERENCED);
                        if (pass == 3)
                        if (labfound == 2) {
			    if (a78flag == 0)
                        	sprintf(linebuff,"    %s",stella[d1]);
			    else
                        	sprintf(linebuff,"    %s",maria[d1]);
                            strcat(nextline,linebuff);
                        } else {
                             sprintf(linebuff,"    $%0.2X ",d1);
                             strcat(nextline,linebuff);
                        }
                    break;
                }
                case IMMEDIATE: {
                    d1=mem[pc++];
                    if (pass == 3) {
                        sprintf(linebuff,"    #$%0.2X ",d1);
                        strcat(nextline,linebuff);
                    }
                    break;
                }
                case ABSOLUTE_X: {
                    ad=read_adr();
                    labfound = mark(ad,REFERENCED);
                    if (pass == 3) {
                        if (ad < 0x100 && fflag) {
                            sprintf(linebuff,".wx ");
                            strcat(nextline,linebuff);
                        }
                        else {
                            sprintf(linebuff,"    ");
                            strcat(nextline,linebuff);
                        }
                        if (labfound == 1) {
                            sprintf(linebuff,"L%0.4X,X",ad);
                            strcat(nextline,linebuff);
                        }
                        else if (labfound == 3) {
			    if (a78flag == 0)
                                sprintf(linebuff,"%s,X",ioregs[ad-0x280]);
			    else
                                sprintf(linebuff,"%s,X",mariaio[ad-0x280]);
                            strcat(nextline,linebuff);
                        }
                        else if (labfound == 5) {
                            sprintf(linebuff,"%s,X",pokey[ad-0x4000]);
                            strcat(nextline,linebuff);
                        }
                        else if ((labfound == 4) && rflag) {
                            sprintf(linebuff,"L%0.4X,X",(ad & app_data.end)+offset);
                            strcat(nextline,linebuff);
                        }
                        else {
                            sprintf(linebuff,"$%0.4X,X",ad);
                            strcat(nextline,linebuff);
                        }
                    }
                    break;
                }
                case ABSOLUTE_Y: {
                    ad=read_adr();
                    labfound = mark(ad,REFERENCED);
                    if (pass == 3) {
                        if (ad < 0x100 && fflag) {
                            sprintf(linebuff,".wy ");
                            strcat(nextline,linebuff);
                        }
                        else {
                            sprintf(linebuff,"    ");
                            strcat(nextline,linebuff);
                        }
                        if (labfound == 1) {
                            sprintf(linebuff,"L%0.4X,Y",ad);
                            strcat(nextline,linebuff);
                        }
                        else if (labfound == 3) {
			    if (a78flag == 0)
                                sprintf(linebuff,"%s,Y",ioregs[ad-0x280]);
			    else
                                sprintf(linebuff,"%s,Y",mariaio[ad-0x280]);
                            strcat(nextline,linebuff);
                        }
                        else if (labfound == 5) {
                            sprintf(linebuff,"%s,Y",pokey[ad-0x4000]);
                            strcat(nextline,linebuff);
                        }
                        else if ((labfound == 4) && rflag) {
                            sprintf(linebuff,"L%0.4X,Y",(ad & app_data.end)+offset);
                            strcat(nextline,linebuff);
                        }
                        else {
                            sprintf(linebuff,"$%0.4X,Y",ad);
                            strcat(nextline,linebuff);
                        }
                    }
                    break;
                }
                case INDIRECT_X: {
                    d1=mem[pc++];
                    if (pass == 3) {
                        sprintf(linebuff,"    ($%0.2X,X)",d1);
                        strcat(nextline,linebuff);
                    }
                    break;
                }
                case INDIRECT_Y: {
                    d1=mem[pc++];
                    if (pass == 3) {
                        sprintf(linebuff,"    ($%0.2X),Y",d1);
                        strcat(nextline,linebuff);
                    }
                    break;
                }
                case ZERO_PAGE_X: {
                    d1=mem[pc++];
                    labfound = mark(d1,REFERENCED);
                    if (pass == 3)
                        if (labfound == 2) {
			    if (a78flag == 0)
                                sprintf(linebuff,"    %s,X",stella[d1]);
			    else
                                sprintf(linebuff,"    %s,X",maria[d1]);
                            strcat(nextline,linebuff);
                        }
                        else {
                            sprintf(linebuff,"    $%0.2X,X",d1);
                            strcat(nextline,linebuff);
                        }
                    break;
                }
                case ZERO_PAGE_Y: {
                    d1=mem[pc++];
                    labfound = mark(d1,REFERENCED);
                    if (pass == 3)
                        if (labfound == 2) {
			    if (a78flag == 0)
                                sprintf(linebuff,"    %s,Y",stella[d1]);
			    else
                                sprintf(linebuff,"    %s,Y",maria[d1]);
                            strcat(nextline,linebuff);
                        }
                        else {
                            sprintf(linebuff,"    $%0.2X,Y",d1);
                            strcat(nextline,linebuff);
                        }
                    break;
                }
                case RELATIVE:
                {
                    d1=mem[pc++];
                    ad=d1;
                    if (d1 >= 128) ad=d1-256;
                    labfound = mark(pc+ad+offset,REFERENCED);
                    if (pass == 1) {
                        if ((addbranch) && !check_bit(labels[pc+ad],REACHABLE)) {
                            addressq=addq(addressq,pc+ad+offset);
                            mark(pc+ad+offset,REACHABLE);
                     /*       addressq=addq(addressq,pc+offset); */
                        }
                    } else if (pass == 3)
                        if (labfound == 1) {
                            sprintf(linebuff,"    L%0.4X",pc+ad+offset);
                            strcat(nextline,linebuff);
                        }
                        else {
                            sprintf(linebuff,"    $%0.4X",pc+ad+offset);
                            strcat(nextline,linebuff);
                        }

                    break;
                }
                case ABS_INDIRECT: {
                    ad=read_adr();
                    labfound = mark(ad,REFERENCED);
                    if (pass == 3)
                        if (ad < 0x100 && fflag) {
                            sprintf(linebuff,".ind ");
                            strcat(nextline,linebuff);
                        }
                        else {
                            sprintf(linebuff,"    ");
                            strcat(nextline,linebuff);
                        }
                        if (labfound == 1) {
                            sprintf(linebuff,"(L%04X)",ad);
                            strcat(nextline,linebuff);
                        }
                        else if (labfound == 3) {
			    if (a78flag == 0)
                                sprintf(linebuff,"(%s)",ioregs[ad-0x280]);
			    else
                                sprintf(linebuff,"(%s)",mariaio[ad-0x280]);
                            strcat(nextline,linebuff);
                        }
                        else if (labfound == 5) {
                            sprintf(linebuff,"(%s)",pokey[ad-0x4000]);
                            strcat(nextline,linebuff);
                        }
                        else {
                            sprintf(linebuff,"($%04X)",ad);
                            strcat(nextline,linebuff);
                        }
                    break;
                }
            }
            if (pass == 1) {
                if (!strcmp(lookup[op].mnemonic,"RTS") ||
                    !strcmp(lookup[op].mnemonic,"JMP") ||
/*                    !strcmp(lookup[op].mnemonic,"BRK") || */
                    !strcmp(lookup[op].mnemonic,"RTI")) {
                        pcend = (pc-1) + offset;
                        return;
                    }
            } else if (pass == 3) {
                printf("%s",nextline);
		if (strlen(nextline) <= 15)
                {
                    /* Print spaces to allign cycle count data */
                    for (charcnt = 0;charcnt < 15 - strlen(nextline); charcnt++)
                        printf(" ");
                }
                if (sflag)
                    printf(";%d",lookup[op].cycles);
                printf("\n");
                if (op == 0x40 || op == 0x60)
                    printf("\n");
                strcpy(nextline,"");
            }
        }
    }    /* while loop */
    /* Just in case we are disassembling outside of the address range, force the pcend to EOF */
    pcend = app_data.end + offset;
}

int mark(unsigned long address,int bit)
{

    /*-----------------------------------------------------------------------
        For any given offset and code range...

	If we're bewteen the offset and the end of the code range, we mark
        the bit in the labels array for that data.  The labels array is an
        array of label info for each code address.  If this is the case,
        return "1", else...

	We sweep for hardware/system equates, which are valid addresses,
        outside the scope of the code/data range.  For these, we mark its
        corresponding hardware/system array element, and return "2", "3", or
        "5" (depending on which system/hardware element was accesed).  If this
        was not the case...

        Next we check if it is a code "mirror".  For the 2600, address ranges
        are limited with 13 bits, so other addresses can exist outside of the
        standard code/data range.  For these, we mark the element in the "labels"
        array that corresponds to the mirrored address, and return "4"

        If all else fails, it's not a valid address, so return 0.



        A quick example breakdown for a 2600 4K cart:
        ===========================================================
        $00-$3d = system equates (WSYNC, etc...); mark the array's element
                      with the appropriate bit; return 2.
        $0280-$0297 = system equates (INPT0, etc...); mark the array's element
                      with the appropriate bit; return 3.
        $1000-$1FFF = CODE/DATA, mark the code/data array for the mirrored address
                      with the appropriate bit; return 4.
        $3000-$3FFF = CODE/DATA, mark the code/data array for the mirrored address
                      with the appropriate bit; return 4.
        $5000-$5FFF = CODE/DATA, mark the code/data array for the mirrored address
                      with the appropriate bit; return 4.
        $7000-$7FFF = CODE/DATA, mark the code/data array for the mirrored address
                      with the appropriate bit; return 4.
        $9000-$9FFF = CODE/DATA, mark the code/data array for the mirrored address
                      with the appropriate bit; return 4.
        $B000-$BFFF = CODE/DATA, mark the code/data array for the mirrored address
                      with the appropriate bit; return 4.
        $D000-$DFFF = CODE/DATA, mark the code/data array for the mirrored address
                      with the appropriate bit; return 4.
        $F000-$FFFF = CODE/DATA, mark the code/data array for the address
                      with the appropriate bit; return 1.
        Anything else = invalid, return 0.
        ===========================================================
    -----------------------------------------------------------------------*/

    if (address >= offset && address <=app_data.end + offset) {
        labels[address-offset] = labels[address-offset] | bit;
        return 1;
    } else if (address >= 0 && address <=0x3d && a78flag == 0) {
        reserved[address] = 1;
        return 2;
    } else if (address >= 0x280 && address <=0x297 && a78flag == 0) {
        ioresrvd[address-0x280] = 1;
        return 3;
    } else if (address >= 0 && address <=0x3f && a78flag == 1) {
        reserved[address] = 1;
        return 2;
    } else if (address >= 0x280 && address <=0x283 && a78flag == 1) {
        ioresrvd[address-0x280] = 1;
        return 3;
    } else if (address >= 0x4000 && address <= 0x400f && a78flag == 1 && kflag == 1) {
        pokresvd[address-0x4000] = 1;
        return 5;
    } else if (address > 0x8000 && a78flag==1 && app_data.end==0x3FFF) {
	/* 16K case */
        labels[address & app_data.end] = labels[address & app_data.end] | bit;
        return 4;
    } else if (address > 0x4000 && address <= 0x7fff && a78flag==1 && app_data.end==0x7fff) {
	/* 32K case */
        labels[address - 0x4000] = labels[address - 0x4000] | bit;
        return 4;
    } else if (address > 0x1000 && a78flag == 0) {
	/* 2K & 4K case */
        labels[address & app_data.end] = labels[address & app_data.end] | bit;
        return 4;
    } else
        return 0;
}

int check_bit(BYTE bitflags, int i)
{
    int j;

    bitflags = bitflags & i;
    j = (int) bitflags;
    return j;
}

void showgfx(unsigned char c)
{
	int i;

    printf("|");
    for(i=0;i<8;i++) {
        if (c > 127)
            printf("X");
        else
            printf(" ");
        c = c << 1;
    }
    printf("|");
}
