static char data[] = {
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
   15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
   30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,
   45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
   60,  61,  62,  63,  64,  65,  66,  67,  68,  69,  70,  71,  72,  73,  74,
   75,  76,  77,  78,  79,  80,  81,  82,  83,  84,  85,  86,  87,  88,  89,
   90,  91,  92,  93,  94,  95,  96,  97,  98,  99, 100, 101, 102, 103, 104,
  105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
  120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
  135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
  150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
  165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
  180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
  195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
  210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
  225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
  240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
  255
};

static const NSString *result0  = @"00000000\n";
static const NSString *result1  = @"00000000  00                                                .\n\
00000001\n";
static const NSString *result2  = @"00000000  00 01                                             ..\n\
00000002\n";
static const NSString *result3  = @"00000000  00 01 02                                          ...\n\
00000003\n";
static const NSString *result4  = @"00000000  00 01 02 03                                       ....\n\
00000004\n";
static const NSString *result5  = @"00000000  00 01 02 03 04                                    .....\n\
00000005\n";
static const NSString *result6  = @"00000000  00 01 02 03 04 05                                 ......\n\
00000006\n";
static const NSString *result7  = @"00000000  00 01 02 03 04 05 06                              .......\n\
00000007\n";
static const NSString *result8  = @"00000000  00 01 02 03 04 05 06 07                           ........\n\
00000008\n";
static const NSString *result9  = @"00000000  00 01 02 03 04 05 06 07  08                       .........\n\
00000009\n";
static const NSString *result10 = @"00000000  00 01 02 03 04 05 06 07  08 09                    ..........\n\
0000000a\n";
static const NSString *result11 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a                 ...........\n\
0000000b\n";
static const NSString *result12 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b              ............\n\
0000000c\n";
static const NSString *result13 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c           .............\n\
0000000d\n";
static const NSString *result14 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d        ..............\n\
0000000e\n";
static const NSString *result15 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e     ...............\n\
0000000f\n";
static const NSString *result16 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010\n";
static const NSString *result17 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10                                                .\n\
00000011\n";
static const NSString *result18 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11                                             ..\n\
00000012\n";
static const NSString *result19 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12                                          ...\n\
00000013\n";
static const NSString *result20 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13                                       ....\n\
00000014\n";
static const NSString *result21 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14                                    .....\n\
00000015\n";
static const NSString *result22 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15                                 ......\n\
00000016\n";
static const NSString *result23 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16                              .......\n\
00000017\n";
static const NSString *result24 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17                           ........\n\
00000018\n";
static const NSString *result25 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18                       .........\n\
00000019\n";
static const NSString *result26 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19                    ..........\n\
0000001a\n";
static const NSString *result27 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a                 ...........\n\
0000001b\n";
static const NSString *result28 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b              ............\n\
0000001c\n";
static const NSString *result29 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c           .............\n\
0000001d\n";
static const NSString *result30 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d        ..............\n\
0000001e\n";
static const NSString *result31 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e     ...............\n\
0000001f\n";
static const NSString *result32 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020\n";
static const NSString *result33 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20                                                 \n\
00000021\n";
static const NSString *result34 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21                                              !\n\
00000022\n";
static const NSString *result35 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22                                           !\"\n\
00000023\n";
static const NSString *result36 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23                                        !\"#\n\
00000024\n";
static const NSString *result37 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24                                     !\"#$\n\
00000025\n";
static const NSString *result38 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25                                  !\"#$%\n\
00000026\n";
static const NSString *result39 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26                               !\"#$%&\n\
00000027\n";
static const NSString *result40 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27                            !\"#$%&'\n\
00000028\n";
static const NSString *result41 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28                        !\"#$%&'(\n\
00000029\n";
static const NSString *result42 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29                     !\"#$%&'()\n\
0000002a\n";
static const NSString *result43 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a                  !\"#$%&'()*\n\
0000002b\n";
static const NSString *result44 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b               !\"#$%&'()*+\n\
0000002c\n";
static const NSString *result45 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c            !\"#$%&'()*+,\n\
0000002d\n";
static const NSString *result46 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d         !\"#$%&'()*+,-\n\
0000002e\n";
static const NSString *result47 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e      !\"#$%&'()*+,-.\n\
0000002f\n";
static const NSString *result48 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030\n";
static const NSString *result49 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30                                                0\n\
00000031\n";
static const NSString *result50 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31                                             01\n\
00000032\n";
static const NSString *result51 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31 32                                          012\n\
00000033\n";
static const NSString *result52 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31 32 33                                       0123\n\
00000034\n";
static const NSString *result53 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31 32 33 34                                    01234\n\
00000035\n";
static const NSString *result54 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31 32 33 34 35                                 012345\n\
00000036\n";
static const NSString *result55 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31 32 33 34 35 36                              0123456\n\
00000037\n";
static const NSString *result56 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31 32 33 34 35 36 37                           01234567\n\
00000038\n";
static const NSString *result57 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31 32 33 34 35 36 37  38                       012345678\n\
00000039\n";
static const NSString *result58 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31 32 33 34 35 36 37  38 39                    0123456789\n\
0000003a\n";
static const NSString *result59 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31 32 33 34 35 36 37  38 39 3a                 0123456789:\n\
0000003b\n";
static const NSString *result60 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31 32 33 34 35 36 37  38 39 3a 3b              0123456789:;\n\
0000003c\n";
static const NSString *result61 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31 32 33 34 35 36 37  38 39 3a 3b 3c           0123456789:;<\n\
0000003d\n";
static const NSString *result62 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31 32 33 34 35 36 37  38 39 3a 3b 3c 3d        0123456789:;<=\n\
0000003e\n";
static const NSString *result63 = @"00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................\n\
00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ................\n\
00000020  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f   !\"#$%&'()*+,-./\n\
00000030  30 31 32 33 34 35 36 37  38 39 3a 3b 3c 3d 3e     0123456789:;<=>\n\
0000003f\n";

