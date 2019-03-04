#pragma once
/* #define SGVALIB112 */

#define SCANCODE_CURSORUP	72      /* Principal cursor keys. */
#define SCANCODE_CURSORLEFT	75      /* (On numeric keypad.) */
#define SCANCODE_CURSORRIGHT	77
#define SCANCODE_CURSORDOWN	80

#define SCANCODE_CURSORUPLEFT	71      /* Diagonal keypad keys. */
#define SCANCODE_CURSORUPRIGHT	73
#define SCANCODE_CURSORDOWNLEFT	79
#define SCANCODE_CURSORDOWNRIGHT 81

#define SCANCODE_CURSORBLOCKUP	103     /* Cursor key block. */
#define SCANCODE_CURSORBLOCKLEFT 105
#define SCANCODE_CURSORBLOCKRIGHT 106
#define SCANCODE_CURSORBLOCKDOWN 108

#define SCANCODE_KEYPAD0	82
#define SCANCODE_KEYPAD1	79
#define SCANCODE_KEYPAD2	80
#define SCANCODE_KEYPAD3	81
#define SCANCODE_KEYPAD4	75
#define SCANCODE_KEYPAD5	76
#define SCANCODE_KEYPAD6	77
#define SCANCODE_KEYPAD7	71
#define SCANCODE_KEYPAD8	72
#define SCANCODE_KEYPAD9	73
#define SCANCODE_KEYPADENTER	96
#define SCANCODE_KEYPADPLUS	78
#define SCANCODE_KEYPADMINUS	74

#define SCANCODE_Q		16
#define SCANCODE_W		17
#define SCANCODE_E		18
#define SCANCODE_R		19
#define SCANCODE_T		20
#define SCANCODE_Y		21
#define SCANCODE_U		22
#define SCANCODE_I		23
#define SCANCODE_O		24
#define SCANCODE_P		25
#define SCANCODE_A		30
#define SCANCODE_S		31
#define SCANCODE_D		32
#define SCANCODE_F		33
#define SCANCODE_G		34
#define SCANCODE_H		35
#define SCANCODE_J		36
#define SCANCODE_K		37
#define SCANCODE_L		38
#define SCANCODE_Z		44
#define SCANCODE_X		45
#define SCANCODE_C		46
#define SCANCODE_V		47
#define SCANCODE_B		48
#define SCANCODE_N		49
#define SCANCODE_M		50

#define SCANCODE_FSLASH         53
#define SCANCODE_BSLASH         43

#define SCANCODE_ESCAPE		1
#define SCANCODE_ENTER		28
#define SCANCODE_RIGHTCONTROL	97
#define SCANCODE_CONTROL	97
#define SCANCODE_RIGHTALT	100
#define SCANCODE_LEFTCONTROL	29
#define SCANCODE_LEFTALT	56

#define SCANCODE_SPACE		57
#define SCANCODE_LEFTSHIFT	42
#define SCANCODE_RIGHTSHIFT	54
#define SCANCODE_TAB		15
#define SCANCODE_CAPSLOCK	58
#define SCANCODE_BACKSPACE	14

#ifdef SGVALIB112

# define SCANCODE_F1             41
# define SCANCODE_F2             42
# define SCANCODE_F3             43
# define SCANCODE_F4             44
# define SCANCODE_F5             45
# define SCANCODE_F6             46
# define SCANCODE_F7             47
# define SCANCODE_F8             48
# define SCANCODE_F9             49
# define SCANCODE_F10            50

#else

# define SCANCODE_F1             59
# define SCANCODE_F2             60
# define SCANCODE_F3             61
# define SCANCODE_F4             62
# define SCANCODE_F5             63
# define SCANCODE_F6             64
# define SCANCODE_F7             65
# define SCANCODE_F8             66
# define SCANCODE_F9             67
# define SCANCODE_F10            68

# define SCANCODE_F11            87
# define SCANCODE_F12            88

#endif

#define SCANCODE_1		2
#define SCANCODE_2              3
#define SCANCODE_3              4
#define SCANCODE_4              5
#define SCANCODE_5              6
#define SCANCODE_6              7
#define SCANCODE_7              8
#define SCANCODE_8              9
#define SCANCODE_9              10
#define SCANCODE_0              11

#define SCANCODE_DASH		12
#define SCANCODE_EQUAL		13

#define SCANCODE_PAGEUP		104
#define SCANCODE_PAGEDOWN       109
#define SCANCODE_HOME           102
#define SCANCODE_END            107
#define SCANCODE_INSERT         110
#define SCANCODE_DELETE         111

#define SCANCODE_COMMA          51
#define SCANCODE_POINT          52

char scancode[255];
void init_scancode (
)
{
  scancode[SCANCODE_KEYPAD0] = '0';
  scancode[SCANCODE_KEYPAD1] = '1';
  scancode[SCANCODE_KEYPAD2] = '2';
  scancode[SCANCODE_KEYPAD3] = '3';
  scancode[SCANCODE_KEYPAD4] = '4';
  scancode[SCANCODE_KEYPAD5] = '5';
  scancode[SCANCODE_KEYPAD6] = '6';
  scancode[SCANCODE_KEYPAD7] = '7';
  scancode[SCANCODE_KEYPAD8] = '8';
  scancode[SCANCODE_KEYPAD9] = '9';

  scancode[SCANCODE_0] = '0';
  scancode[SCANCODE_1] = '1';
  scancode[SCANCODE_2] = '2';
  scancode[SCANCODE_3] = '3';
  scancode[SCANCODE_4] = '4';
  scancode[SCANCODE_5] = '5';
  scancode[SCANCODE_6] = '6';
  scancode[SCANCODE_7] = '7';
  scancode[SCANCODE_8] = '8';
  scancode[SCANCODE_9] = '9';

  scancode[SCANCODE_Q] = 'Q';
  scancode[SCANCODE_W] = 'W';
  scancode[SCANCODE_E] = 'E';
  scancode[SCANCODE_R] = 'R';
  scancode[SCANCODE_T] = 'T';
  scancode[SCANCODE_Y] = 'Y';
  scancode[SCANCODE_U] = 'U';
  scancode[SCANCODE_I] = 'I';
  scancode[SCANCODE_O] = 'O';
  scancode[SCANCODE_P] = 'P';
  scancode[SCANCODE_A] = 'A';
  scancode[SCANCODE_S] = 'S';
  scancode[SCANCODE_D] = 'D';
  scancode[SCANCODE_F] = 'F';
  scancode[SCANCODE_G] = 'G';
  scancode[SCANCODE_H] = 'H';
  scancode[SCANCODE_J] = 'J';
  scancode[SCANCODE_K] = 'K';
  scancode[SCANCODE_L] = 'L';
  scancode[SCANCODE_Z] = 'Z';
  scancode[SCANCODE_X] = 'X';
  scancode[SCANCODE_C] = 'C';
  scancode[SCANCODE_V] = 'V';
  scancode[SCANCODE_B] = 'B';
  scancode[SCANCODE_N] = 'N';
  scancode[SCANCODE_M] = 'M';
}
