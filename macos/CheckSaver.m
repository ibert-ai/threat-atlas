#import <Cocoa/Cocoa.h>
#import <ScreenSaver/ScreenSaver.h>
// Offline host lifecycle smoke test: a Settings view must render without startAnimation.
static BOOL hasContent(ScreenSaverView *view) {
    NSBitmapImageRep *bitmap=[view bitmapImageRepForCachingDisplayInRect:view.bounds];
    if (!bitmap) return NO;
    [view cacheDisplayInRect:view.bounds toBitmapImageRep:bitmap];
    NSMutableSet *colors=[NSMutableSet new];
    for (NSInteger y=0;y<bitmap.pixelsHigh;y+=8) for (NSInteger x=0;x<bitmap.pixelsWide;x+=8) {
        NSColor *color=[[bitmap colorAtX:x y:y] colorUsingColorSpace:NSColorSpace.deviceRGBColorSpace];
        if (color) [colors addObject:@[@((int)(color.redComponent*255)),@((int)(color.greenComponent*255)),@((int)(color.blueComponent*255))]];
    }
    return colors.count>12;
}
int main(int argc,char **argv) {@autoreleasepool {
    if (argc!=2) return 2;
    [NSApplication sharedApplication];
    NSBundle *bundle=[NSBundle bundleWithPath:[NSString stringWithUTF8String:argv[1]]];NSError *error=nil;
    if (![bundle loadAndReturnError:&error] || ![bundle.principalClass isSubclassOfClass:ScreenSaverView.class]) {NSLog(@"Bundle load failed: %@",error);return 1;}
    for (NSString *name in @[@"thumbnail",@"thumbnail@2x"]) {
        NSImage *image=[[NSImage alloc] initWithContentsOfURL:[bundle URLForResource:name withExtension:@"png"]];
        if (!image.isValid) {NSLog(@"Missing or invalid screenshot thumbnail: %@",name);return 1;}
    }
    for (int preview=0;preview<2;preview++) {
        ScreenSaverView *view=[[bundle.principalClass alloc] initWithFrame:NSMakeRect(0,0,720,450) isPreview:preview];
        if (!hasContent(view)) {NSLog(@"Blank first frame before window attachment");return 1;}
        NSWindow *window=[[NSWindow alloc] initWithContentRect:view.bounds styleMask:NSWindowStyleMaskBorderless backing:NSBackingStoreBuffered defer:NO];window.releasedWhenClosed=NO;
        window.contentView=view;
        if (!hasContent(view)) {NSLog(@"Blank view before host startAnimation, preview=%d",preview);return 1;}
        [view startAnimation];[view animateOneFrame];
        if (!hasContent(view)) return 1;
        [view stopAnimation];[view startAnimation];
        if (!hasContent(view)) return 1;
        [view stopAnimation];window.contentView=nil;[window close];
    }
    NSLog(@"Bundle load, pre-animation rendering, preview/full-screen and restart passed");return 0;
}}
