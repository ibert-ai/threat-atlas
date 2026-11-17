#import <ScreenSaver/ScreenSaver.h>
#import "../crates/core/include/threat_atlas_saver.h"

@interface ThreatAtlasSOCView : ScreenSaverView
@property(nonatomic) TaSaverSession *session;
@property(nonatomic) uint32_t fittedWindowWidth;
@property(nonatomic) uint32_t frameWidth;
@property(nonatomic, strong) NSTimer *fallbackTimer;
@end
@implementation ThreatAtlasSOCView
- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)preview {
    self=[super initWithFrame:frame isPreview:preview];
    if (self) {self.animationTimeInterval=preview ? 1.0/10.0 : 1.0/20.0;}
    return self;
}
- (void)dealloc {[_fallbackTimer invalidate];if (_session) ta_saver_drop(_session);}
- (void)ensureRendering {
    if (!self.session) self.session=ta_saver_new();
    if (!self.fallbackTimer && self.window) {
        __weak ThreatAtlasSOCView *weakSelf=self;
        self.fallbackTimer=[NSTimer timerWithTimeInterval:self.animationTimeInterval repeats:YES block:^(NSTimer *timer){
            ThreatAtlasSOCView *view=weakSelf;
            if (!view || !view.window) {[timer invalidate];return;}
            [view setNeedsDisplay:YES];
        }];
        [NSRunLoop.mainRunLoop addTimer:self.fallbackTimer forMode:NSRunLoopCommonModes];
    }
    [self setNeedsDisplay:YES];
}
- (void)viewDidMoveToWindow {
    [super viewDidMoveToWindow];
    // Some macOS Settings/legacy hosts attach the view without calling startAnimation.
    if (self.window) {[self ensureRendering];}
    else {[self stopAnimation];}
}
- (void)startAnimation {[super startAnimation];[self ensureRendering];}
- (void)stopAnimation {[self.fallbackTimer invalidate];self.fallbackTimer=nil;if (self.session) {ta_saver_drop(self.session);self.session=NULL;self.fittedWindowWidth=0;self.frameWidth=0;}[super stopAnimation];}
- (void)animateOneFrame {[self setNeedsDisplay:YES];}
- (void)drawRect:(NSRect)dirty {
    [[NSColor colorWithCalibratedRed:6.0/255 green:12.0/255 blue:20.0/255 alpha:1] setFill];NSRectFill(self.bounds);
    if (!self.session) {
        [@"Threat Atlas is starting…" drawAtPoint:NSMakePoint(20,20) withAttributes:@{NSForegroundColorAttributeName:NSColor.whiteColor}];
        return;
    }
    CGFloat backingWidth = [self convertRectToBacking:self.bounds].size.width;
    if (backingWidth < 1 || backingWidth > UINT32_MAX) return;
    uint32_t windowWidth = (uint32_t)backingWidth;
    if (windowWidth != self.fittedWindowWidth) {
        self.frameWidth = ta_saver_fit(self.session, windowWidth);
        self.fittedWindowWidth = windowWidth;
    }
    size_t w = self.frameWidth;
    const size_t h = 900;
    if (!w) return;
    const uint8_t *bytes = ta_saver_frame(self.session);
    if (!bytes) return;
    NSData *pixels = [NSData dataWithBytes:bytes length:w * h * 4];
    CGColorSpaceRef space=CGColorSpaceCreateDeviceRGB();
    CGDataProviderRef provider=CGDataProviderCreateWithCFData((__bridge CFDataRef)pixels);
    CGImageRef image=CGImageCreate(w,h,8,32,w*4,space,kCGImageAlphaPremultipliedLast|kCGBitmapByteOrder32Big,provider,NULL,false,kCGRenderingIntentDefault);
    CGFloat scale=MIN(self.bounds.size.width/w,self.bounds.size.height/h);
    CGFloat dw=w*scale,dh=h*scale;
    CGContextRef context=NSGraphicsContext.currentContext.CGContext;
    CGContextSaveGState(context);
    CGContextTranslateCTM(context,(self.bounds.size.width-dw)/2,(self.bounds.size.height-dh)/2);
    CGContextSetInterpolationQuality(context,kCGInterpolationHigh);
    CGContextDrawImage(context,CGRectMake(0,0,dw,dh),image);
    CGContextRestoreGState(context);
    CGImageRelease(image);CGDataProviderRelease(provider);CGColorSpaceRelease(space);
}
- (BOOL)hasConfigureSheet {return NO;}
@end
