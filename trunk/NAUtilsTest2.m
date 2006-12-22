//
//  NAUtilsTest2.m
//  Network Analyzer
//
//  Created by C. Scott Marshall on 12/19/06.
//  Copyright 2006 __MyCompanyName__. All rights reserved.
//

#import "NAUtilsTest2.h"
#import "NAUtils.h"
#import "NAUtilsTestData2.h"


@implementation NAUtilsTest2


- (void) testHexDump
{
  NSString *s = [NAUtils hexdump: data length: 64];
  STAssertTrue([result64 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 65];
  STAssertTrue([result65 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 66];
  STAssertTrue([result66 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 67];
  STAssertTrue([result67 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 68];
  STAssertTrue([result68 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 69];
  STAssertTrue([result69 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 70];
  STAssertTrue([result70 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 71];
  STAssertTrue([result71 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 72];
  STAssertTrue([result72 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 73];
  STAssertTrue([result73 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 74];
  STAssertTrue([result74 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 75];
  STAssertTrue([result75 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 76];
  STAssertTrue([result76 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 77];
  STAssertTrue([result77 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 78];
  STAssertTrue([result78 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 79];
  STAssertTrue([result79 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 80];
  STAssertTrue([result80 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 81];
  STAssertTrue([result81 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 82];
  STAssertTrue([result82 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 83];
  STAssertTrue([result83 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 84];
  STAssertTrue([result84 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 85];
  STAssertTrue([result85 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 86];
  STAssertTrue([result86 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 87];
  STAssertTrue([result87 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 88];
  STAssertTrue([result88 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 89];
  STAssertTrue([result89 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 90];
  STAssertTrue([result90 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 91];
  STAssertTrue([result91 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 92];
  STAssertTrue([result92 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 93];
  STAssertTrue([result93 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 94];
  STAssertTrue([result94 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 95];
  STAssertTrue([result95 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 96];
  STAssertTrue([result96 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 97];
  STAssertTrue([result97 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 98];
  STAssertTrue([result98 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 99];
  STAssertTrue([result99 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 100];
  STAssertTrue([result100 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 101];
  STAssertTrue([result101 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 102];
  STAssertTrue([result102 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 103];
  STAssertTrue([result103 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 104];
  STAssertTrue([result104 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 105];
  STAssertTrue([result105 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 106];
  STAssertTrue([result106 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 107];
  STAssertTrue([result107 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 108];
  STAssertTrue([result108 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 109];
  STAssertTrue([result109 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 110];
  STAssertTrue([result110 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 111];
  STAssertTrue([result111 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 112];
  STAssertTrue([result112 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 113];
  STAssertTrue([result113 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 114];
  STAssertTrue([result114 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 115];
  STAssertTrue([result115 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 116];
  STAssertTrue([result116 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 117];
  STAssertTrue([result117 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 118];
  STAssertTrue([result118 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 119];
  STAssertTrue([result119 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 120];
  STAssertTrue([result120 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 121];
  STAssertTrue([result121 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 122];
  STAssertTrue([result122 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 123];
  STAssertTrue([result123 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 124];
  STAssertTrue([result124 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 125];
  STAssertTrue([result125 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 126];
  STAssertTrue([result126 isEqual: s], @"got wrong output: %@", s);
  s = [NAUtils hexdump: data length: 127];
  STAssertTrue([result127 isEqual: s], @"got wrong output: %@", s);
}

@end
