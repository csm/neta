//
//  NAUtilsTest.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/19/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import "NAUtilsTest.h"
#import "NAUtils.h"
#import "NAUtilsTestData.h"


@implementation NAUtilsTest


- (void) testHexDump
{
  NSString *s = [NAUtils hexdump: data length: 0];
  STAssertTrue([result0 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 1];
  STAssertTrue([result1 isEqual: s], @"got wrong output: %@", s);
  
  s = [NAUtils hexdump: data length: 2];
  STAssertTrue([result2 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 3];
  STAssertTrue([result3 isEqual: s], @"got wrong output: %@", s);

  s = [NAUtils hexdump: data length: 4];
  STAssertTrue([result4 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 5];
  STAssertTrue([result5 isEqual: s], @"got wrong output: %@", s);

  s = [NAUtils hexdump: data length: 6];
  STAssertTrue([result6 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 7];
  STAssertTrue([result7 isEqual: s], @"got wrong output: %@", s);

  s = [NAUtils hexdump: data length: 8];
  STAssertTrue([result8 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 9];
  STAssertTrue([result9 isEqual: s], @"got wrong output: %@", s);

  s = [NAUtils hexdump: data length: 10];
  STAssertTrue([result10 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 11];
  STAssertTrue([result11 isEqual: s], @"got wrong output: %@", s);

  s = [NAUtils hexdump: data length: 12];
  STAssertTrue([result12 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 13];
  STAssertTrue([result13 isEqual: s], @"got wrong output: %@", s);
  
  s = [NAUtils hexdump: data length: 14];
  STAssertTrue([result14 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 15];
  STAssertTrue([result15 isEqual: s], @"got wrong output: %@", s);
  
  s = [NAUtils hexdump: data length: 16];
  STAssertTrue([result16 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 17];
  STAssertTrue([result17 isEqual: s], @"got wrong output: %@", s);
  
  s = [NAUtils hexdump: data length: 18];
  STAssertTrue([result18 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 19];
  STAssertTrue([result19 isEqual: s], @"got wrong output: %@", s);
  
  s = [NAUtils hexdump: data length: 20];
  STAssertTrue([result20 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 21];
  STAssertTrue([result21 isEqual: s], @"got wrong output: %@", s);
  
  s = [NAUtils hexdump: data length: 22];
  STAssertTrue([result22 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 23];
  STAssertTrue([result23 isEqual: s], @"got wrong output: %@", s);
    s = [NAUtils hexdump: data length: 24];
  STAssertTrue([result24 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 25];
  STAssertTrue([result25 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 26];
  STAssertTrue([result26 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 27];
  STAssertTrue([result27 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 28];
  STAssertTrue([result28 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 29];
  STAssertTrue([result29 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 30];
  STAssertTrue([result30 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 31];
  STAssertTrue([result31 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 32];
  STAssertTrue([result32 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 33];
  STAssertTrue([result33 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 34];
  STAssertTrue([result34 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 35];
  STAssertTrue([result35 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 36];
  STAssertTrue([result36 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 37];
  STAssertTrue([result37 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 38];
  STAssertTrue([result38 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 39];
  STAssertTrue([result39 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 40];
  STAssertTrue([result40 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 41];
  STAssertTrue([result41 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 42];
  STAssertTrue([result42 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 43];
  STAssertTrue([result43 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 44];
  STAssertTrue([result44 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 45];
  STAssertTrue([result45 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 46];
  STAssertTrue([result46 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 47];
  STAssertTrue([result47 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 48];
  STAssertTrue([result48 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 49];
  STAssertTrue([result49 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 50];
  STAssertTrue([result50 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 51];
  STAssertTrue([result51 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 52];
  STAssertTrue([result52 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 53];
  STAssertTrue([result53 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 54];
  STAssertTrue([result54 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 55];
  STAssertTrue([result55 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 56];
  STAssertTrue([result56 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 57];
  STAssertTrue([result57 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 58];
  STAssertTrue([result58 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 59];
  STAssertTrue([result59 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 60];
  STAssertTrue([result60 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 61];
  STAssertTrue([result61 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 62];
  STAssertTrue([result62 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 63];
  STAssertTrue([result63 isEqual: s], @"got wrong output: %@", s);
}

@end
