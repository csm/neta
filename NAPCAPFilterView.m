/* NAPCAPFilterView.m -- custom view for pcap filter predicates.
   Copyright (C) 2006, 2007  Casey Marshall <casey.s.marshall@gmail.com>

This file is a part of Network Analyzer.

Network Analyzer is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301  USA  */


#import "NAPCAPFilterView.h"

@implementation NAPCAPFilterView

- (id) initWithFrame: (NSRect) frameRect
{
	if ((self = [super initWithFrame: frameRect]) != nil)
  {
    backgroundColor = [[NSColor whiteColor] retain];
	}
	return self;
}

- (BOOL) acceptsFirstMouse: (NSEvent *) anEvent
{
  return NO;
}

- (void) drawRect: (NSRect) rect
{
  [backgroundColor set];
  NSRectFill ([self bounds]);
}

- (void) setBackground: (NSColor *) aColor
{
  [backgroundColor release];
  backgroundColor = aColor;
  [aColor retain];
}

- (void) dealloc
{
  [backgroundColor release];
  [super dealloc];
}

@end
