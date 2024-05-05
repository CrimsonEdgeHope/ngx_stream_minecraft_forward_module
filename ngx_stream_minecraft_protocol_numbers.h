/*
 Reference to modern Minecraft Java protocol.

 https://wiki.vg
*/

#ifndef _NGX_STREAM_MINECRAFT_PROTOCOL_NUMBERS_H_
#define _NGX_STREAM_MINECRAFT_PROTOCOL_NUMBERS_H_

#include "ngx_stream_minecraft_forward_module.h"

#define MINECRAFT_1_8 47
#define MINECRAFT_1_8_1 47
#define MINECRAFT_1_8_2 47
#define MINECRAFT_1_8_3 47
#define MINECRAFT_1_8_4 47
#define MINECRAFT_1_8_5 47
#define MINECRAFT_1_8_6 47
#define MINECRAFT_1_8_7 47
#define MINECRAFT_1_8_8 47
#define MINECRAFT_1_8_9 47

#define MINECRAFT_1_9 107
#define MINECRAFT_1_9_1 108
#define MINECRAFT_1_9_2 109
#define MINECRAFT_1_9_3 110
#define MINECRAFT_1_9_4 110

#define MINECRAFT_1_10 210
#define MINECRAFT_1_10_1 210
#define MINECRAFT_1_10_2 210

#define MINECRAFT_1_11 315
#define MINECRAFT_1_11_1 316
#define MINECRAFT_1_11_2 316

#define MINECRAFT_1_12 335
#define MINECRAFT_1_12_1 338
#define MINECRAFT_1_12_2 340

#define MINECRAFT_1_13 393
#define MINECRAFT_1_13_1 401
#define MINECRAFT_1_13_2 404

#define MINECRAFT_1_14 477
#define MINECRAFT_1_14_1 480
#define MINECRAFT_1_14_2 485
#define MINECRAFT_1_14_3 490
#define MINECRAFT_1_14_4 498

#define MINECRAFT_1_15 573
#define MINECRAFT_1_15_1 575
#define MINECRAFT_1_15_2 578

#define MINECRAFT_1_16 735
#define MINECRAFT_1_16_1 736
#define MINECRAFT_1_16_2 751
#define MINECRAFT_1_16_3 753
#define MINECRAFT_1_16_4 754
#define MINECRAFT_1_16_5 754

#define MINECRAFT_1_17 755
#define MINECRAFT_1_17_1 756

#define MINECRAFT_1_18 757
#define MINECRAFT_1_18_1 757
#define MINECRAFT_1_18_2 758

#define MINECRAFT_1_19 759
#define MINECRAFT_1_19_1 760
#define MINECRAFT_1_19_2 760
#define MINECRAFT_1_19_3 761
#define MINECRAFT_1_19_4 762

#define MINECRAFT_1_20 763
#define MINECRAFT_1_20_1 763
#define MINECRAFT_1_20_2 764
#define MINECRAFT_1_20_3 765
#define MINECRAFT_1_20_4 765

ngx_int_t is_protocol_num_acceptable(ngx_stream_minecraft_protocol_number_t nt);

#endif
