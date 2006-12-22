//
//  NAUtilsTest4.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/19/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import "NAUtilsTest4.h"
#import "NAUtils.h"
#import "NAUtilsTestData4.h"


@implementation NAUtilsTest4


- (void) testHexDump
{
  NSString *s = [NAUtils hexdump: data length: 192];
  STAssertTrue([result192 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 193];
  STAssertTrue([result193 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 194];
  STAssertTrue([result194 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 195];
  STAssertTrue([result195 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 196];
  STAssertTrue([result196 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 197];
  STAssertTrue([result197 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 198];
  STAssertTrue([result198 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 199];
  STAssertTrue([result199 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 200];
  STAssertTrue([result200 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 201];
  STAssertTrue([result201 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 202];
  STAssertTrue([result202 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 203];
  STAssertTrue([result203 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 204];
  STAssertTrue([result204 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 205];
  STAssertTrue([result205 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 206];
  STAssertTrue([result206 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 207];
  STAssertTrue([result207 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 208];
  STAssertTrue([result208 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 209];
  STAssertTrue([result209 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 210];
  STAssertTrue([result210 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 211];
  STAssertTrue([result211 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 212];
  STAssertTrue([result212 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 213];
  STAssertTrue([result213 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 214];
  STAssertTrue([result214 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 215];
  STAssertTrue([result215 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 216];
  STAssertTrue([result216 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 217];
  STAssertTrue([result217 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 218];
  STAssertTrue([result218 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 219];
  STAssertTrue([result219 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 220];
  STAssertTrue([result220 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 221];
  STAssertTrue([result221 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 222];
  STAssertTrue([result222 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 223];
  STAssertTrue([result223 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 224];
  STAssertTrue([result224 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 225];
  STAssertTrue([result225 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 226];
  STAssertTrue([result226 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 227];
  STAssertTrue([result227 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 228];
  STAssertTrue([result228 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 229];
  STAssertTrue([result229 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 230];
  STAssertTrue([result230 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 231];
  STAssertTrue([result231 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 232];
  STAssertTrue([result232 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 233];
  STAssertTrue([result233 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 234];
  STAssertTrue([result234 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 235];
  STAssertTrue([result235 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 236];
  STAssertTrue([result236 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 237];
  STAssertTrue([result237 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 238];
  STAssertTrue([result238 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 239];
  STAssertTrue([result239 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 240];
  STAssertTrue([result240 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 241];
  STAssertTrue([result241 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 242];
  STAssertTrue([result242 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 243];
  STAssertTrue([result243 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 244];
  STAssertTrue([result244 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 245];
  STAssertTrue([result245 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 246];
  STAssertTrue([result246 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 247];
  STAssertTrue([result247 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 248];
  STAssertTrue([result248 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 249];
  STAssertTrue([result249 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 250];
  STAssertTrue([result250 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 251];
  STAssertTrue([result251 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 252];
  STAssertTrue([result252 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 253];
  STAssertTrue([result253 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 254];
  STAssertTrue([result254 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 255];
  STAssertTrue([result255 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 256];
  STAssertTrue([result256 isEqual: s], @"got wrong output: %@", s);
}

@end
