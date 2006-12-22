//
//  NAUtilsTest3.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/19/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import "NAUtilsTest3.h"
#import "NAUtils.h"
#import "NAUtilsTestData3.h"


@implementation NAUtilsTest3


- (void) testHexDump
{
  NSString *s = [NAUtils hexdump: data length: 128];
  STAssertTrue([result128 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 129];
  STAssertTrue([result129 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 130];
  STAssertTrue([result130 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 131];
  STAssertTrue([result131 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 132];
  STAssertTrue([result132 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 133];
  STAssertTrue([result133 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 134];
  STAssertTrue([result134 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 135];
  STAssertTrue([result135 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 136];
  STAssertTrue([result136 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 137];
  STAssertTrue([result137 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 138];
  STAssertTrue([result138 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 139];
  STAssertTrue([result139 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 140];
  STAssertTrue([result140 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 141];
  STAssertTrue([result141 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 142];
  STAssertTrue([result142 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 143];
  STAssertTrue([result143 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 144];
  STAssertTrue([result144 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 145];
  STAssertTrue([result145 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 146];
  STAssertTrue([result146 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 147];
  STAssertTrue([result147 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 148];
  STAssertTrue([result148 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 149];
  STAssertTrue([result149 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 150];
  STAssertTrue([result150 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 151];
  STAssertTrue([result151 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 152];
  STAssertTrue([result152 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 153];
  STAssertTrue([result153 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 154];
  STAssertTrue([result154 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 155];
  STAssertTrue([result155 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 156];
  STAssertTrue([result156 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 157];
  STAssertTrue([result157 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 158];
  STAssertTrue([result158 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 159];
  STAssertTrue([result159 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 160];
  STAssertTrue([result160 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 161];
  STAssertTrue([result161 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 162];
  STAssertTrue([result162 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 163];
  STAssertTrue([result163 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 164];
  STAssertTrue([result164 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 165];
  STAssertTrue([result165 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 166];
  STAssertTrue([result166 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 167];
  STAssertTrue([result167 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 168];
  STAssertTrue([result168 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 169];
  STAssertTrue([result169 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 170];
  STAssertTrue([result170 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 171];
  STAssertTrue([result171 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 172];
  STAssertTrue([result172 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 173];
  STAssertTrue([result173 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 174];
  STAssertTrue([result174 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 175];
  STAssertTrue([result175 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 176];
  STAssertTrue([result176 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 177];
  STAssertTrue([result177 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 178];
  STAssertTrue([result178 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 179];
  STAssertTrue([result179 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 180];
  STAssertTrue([result180 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 181];
  STAssertTrue([result181 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 182];
  STAssertTrue([result182 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 183];
  STAssertTrue([result183 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 184];
  STAssertTrue([result184 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 185];
  STAssertTrue([result185 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 186];
  STAssertTrue([result186 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 187];
  STAssertTrue([result187 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 188];
  STAssertTrue([result188 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 189];
  STAssertTrue([result189 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 190];
  STAssertTrue([result190 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 191];
  STAssertTrue([result191 isEqual: s], @"got wrong output: %@", s);
}

@end
