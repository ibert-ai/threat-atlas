#import <ScreenSaver/ScreenSaver.h>
extern void *ta_new(void);
extern const unsigned char *ta_frame(void *session);
extern void ta_drop(void *session);
extern uint32_t ta_width(void);
extern uint32_t ta_height(void);

@interface ThreatAtlasSOCView : ScreenSaverView
@property(nonatomic) void *session;
@property(nonatomic, strong) NSPanel *options;
@property(nonatomic, strong) NSTimer *fallbackTimer;
@end
@implementation ThreatAtlasSOCView
- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)preview {
    self=[super initWithFrame:frame isPreview:preview];
    if (self) {self.animationTimeInterval=preview ? 1.0/10.0 : 1.0/20.0;self.session=ta_new();}
    return self;
}
- (void)dealloc {[_fallbackTimer invalidate];if (_session) ta_drop(_session);}
- (void)ensureRendering {
    if (!self.session) self.session=ta_new();
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
- (void)stopAnimation {[self.fallbackTimer invalidate];self.fallbackTimer=nil;if (self.session) {ta_drop(self.session);self.session=NULL;}[super stopAnimation];}
- (void)animateOneFrame {[self setNeedsDisplay:YES];}
- (void)drawRect:(NSRect)dirty {
    [[NSColor colorWithCalibratedRed:6.0/255 green:12.0/255 blue:20.0/255 alpha:1] setFill];NSRectFill(self.bounds);
    if (!self.session) {
        [@"Threat Atlas is starting…" drawAtPoint:NSMakePoint(20,20) withAttributes:@{NSForegroundColorAttributeName:NSColor.whiteColor}];
        return;
    }
    const unsigned char *bytes=ta_frame(self.session);if (!bytes) return;
    size_t w=ta_width(),h=ta_height();
    CGColorSpaceRef space=CGColorSpaceCreateDeviceRGB();
    CGDataProviderRef provider=CGDataProviderCreateWithData(NULL,bytes,w*h*4,NULL);
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
- (BOOL)hasConfigureSheet {return YES;}
- (NSWindow *)configureSheet {
    self.options=[[NSPanel alloc] initWithContentRect:NSMakeRect(0,0,520,240) styleMask:NSWindowStyleMaskTitled backing:NSBackingStoreBuffered defer:NO];
    self.options.title=[NSString stringWithFormat:@"Threat Atlas SOC %@", [NSBundle bundleForClass:self.class].infoDictionary[@"CFBundleShortVersionString"]];
    NSTextField *text=[NSTextField wrappingLabelWithString:@"Native Rust SOC display • GreyNoise public telemetry\n\nNo browser, cookie approval, API key or account needed.\n\nLIVE means records arrived within 10 seconds. Routes expire after 6 seconds. Disconnections trigger automatic retry. The header shows UTC and system local time. Observation times are receipt times in UTC; the provider supplies no event timestamps.\n\nUse macOS settings for idle time and password requirements."];
    text.frame=NSMakeRect(20,55,480,170);[self.options.contentView addSubview:text];
    NSButton *done=[NSButton buttonWithTitle:@"Done" target:self action:@selector(closeOptions:)];done.frame=NSMakeRect(405,15,95,32);[self.options.contentView addSubview:done];return self.options;
}
- (void)closeOptions:(id)sender {[self.options.sheetParent endSheet:self.options];}
@end
