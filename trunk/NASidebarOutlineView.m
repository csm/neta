/* NASidebarOutlineView.m -- filters list.
   Copyright (C) 2007  Casey Marshall <casey.s.marshall@gmail.com>
   Parts copyright Timothy Hatcher et al. from the Colloquy project.

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


#import "NASidebarOutlineView.h"

// Parts taken from Colloquy, JVSideOutlineView

static void gradientInterpolate(void *info, float const *inData, float *outData)
{
	static float light[4] = { 0.67843137, 0.73333333, 0.81568627, 1. };
	static float dark[4] = { 0.59607843, 0.66666667, 0.76862745, 1. };
	float a = inData[0];
	int i = 0;
  
	for( i = 0; i < 4; i++ )
		outData[i] = (1. - a) * dark[i] + a * light[i];
}


@implementation NASidebarOutlineView

- (NSColor *) _highlightColorForCell: (NSCell *) cell
{
  return nil;
}

- (void) _highlightRow: (int) row
              clipRect: (NSRect) clip
{
	NSRect highlight = [self rectOfRow:row];
  
	struct CGFunctionCallbacks callbacks = { 0, gradientInterpolate, NULL };
	CGFunctionRef function = CGFunctionCreate( NULL, 1, NULL, 4, NULL, &callbacks );
	CGColorSpaceRef cspace = CGColorSpaceCreateDeviceRGB();
  
	CGShadingRef shading = CGShadingCreateAxial(cspace,
                                              CGPointMake(NSMinX(highlight),
                                                          NSMaxY(highlight)),
                                              CGPointMake(NSMinX(highlight),
                                                          NSMinY(highlight)),
                                              function, false, false);
	CGContextDrawShading([[NSGraphicsContext currentContext] graphicsPort], shading);
  
	CGShadingRelease(shading);
	CGColorSpaceRelease(cspace);
	CGFunctionRelease(function);
  
	static NSColor *rowBottomLine = nil;
	if (!rowBottomLine)
		rowBottomLine = [[NSColor colorWithCalibratedRed: (140. / 255.)
                                               green: (152. / 255.)
                                                blue: (176. / 255.)
                                               alpha: 1.] retain];
  
	[rowBottomLine set];
  
	NSRect bottomLine = NSMakeRect(NSMinX(highlight), NSMaxY(highlight) - 1.,
                                 NSWidth(highlight), 1.);
	NSRectFill(bottomLine);
}

- (void) drawBackgroundInClipRect: (NSRect) rect
{
  static NSColor *background = nil;
  if (background == nil)
  {
    background = [[NSColor colorWithCalibratedRed: 0.914
                                            green: 0.937
                                             blue: 0.98
                                            alpha: 1.0] retain];
  }
  
  [background set];
  NSRectFill(rect);
}

@end
