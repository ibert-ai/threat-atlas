#import <ScreenSaver/ScreenSaver.h>
#import "Radar.h"
extern void *ta_new(void);
extern const unsigned char *ta_frame(void *session);
extern void ta_drop(void *session);
extern uint32_t ta_width(void);
extern uint32_t ta_height(void);

@interface ThreatAtlasSOCView : ScreenSaverView
@property(nonatomic) void *session;
@property(nonatomic, strong) TARadarView *radarView;
@property(nonatomic, strong) NSSecureTextField *radarToken;
@property(nonatomic, strong) NSPanel *options;
@property(nonatomic, strong) NSTimer *fallbackTimer;
@end
@implementation ThreatAtlasSOCView
- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)preview {
    self=[super initWithFrame:frame isPreview:preview];
    if (self) {self.animationTimeInterval=preview ? 1.0/10.0 : 1.0/20.0;self.session=TARadar.licenseAccepted?ta_new():NULL;
        [TARadar.defaults registerDefaults:@{@"TARadarEnabled":@NO,@"TARadarOutages":@YES,@"TARadarTraffic":@YES}];
        self.radarView=[[TARadarView alloc] initWithFrame:NSZeroRect];[self addSubview:self.radarView];}
    return self;
}
- (void)dealloc {[_fallbackTimer invalidate];if (_session) ta_drop(_session);}
- (void)ensureRendering {
    if (!self.session && TARadar.licenseAccepted) self.session=ta_new();
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
        [@"Open Threat Atlas SOC.app and accept the Cloudflare Radar licence for this build. No telemetry connections are started until acceptance." drawAtPoint:NSMakePoint(20,20) withAttributes:@{NSForegroundColorAttributeName:NSColor.whiteColor}];
        return;
    }
    const unsigned char *bytes=ta_frame(self.session);if (!bytes) return;
    size_t w=ta_width(),h=ta_height();
    CGColorSpaceRef space=CGColorSpaceCreateDeviceRGB();
    CGDataProviderRef provider=CGDataProviderCreateWithData(NULL,bytes,w*h*4,NULL);
    CGImageRef image=CGImageCreate(w,h,8,32,w*4,space,kCGImageAlphaPremultipliedLast|kCGBitmapByteOrder32Big,provider,NULL,false,kCGRenderingIntentDefault);
    BOOL radar=[TARadar.defaults boolForKey:@"TARadarEnabled"];
    CGFloat pane=radar?MIN(440,self.bounds.size.width*0.45):0;
    self.radarView.hidden=!radar;self.radarView.frame=NSMakeRect(self.bounds.size.width-pane,0,pane,self.bounds.size.height);
    if(radar){[TARadar.shared refresh];[self.radarView setNeedsDisplay:YES];}
    CGFloat canvasWidth=self.bounds.size.width-pane;
    CGFloat scale=MIN(canvasWidth/w,self.bounds.size.height/h);
    CGFloat dw=w*scale,dh=h*scale;
    CGContextRef context=NSGraphicsContext.currentContext.CGContext;
    CGContextSaveGState(context);
    CGContextTranslateCTM(context,(canvasWidth-dw)/2,(self.bounds.size.height-dh)/2);
    CGContextSetInterpolationQuality(context,kCGInterpolationHigh);
    CGContextDrawImage(context,CGRectMake(0,0,dw,dh),image);
    CGContextRestoreGState(context);
    CGImageRelease(image);CGDataProviderRelease(provider);CGColorSpaceRelease(space);
}
- (BOOL)hasConfigureSheet {return YES;}
- (void)toggleRadar:(NSButton *)sender {
    [TARadar.defaults setBool:sender.state==NSControlStateValueOn forKey:sender.identifier];[self setNeedsDisplay:YES];
}
- (void)saveRadar:(id)sender {
    [TARadar.shared configureToken:self.radarToken.stringValue];self.radarToken.stringValue=@"";
}
- (NSWindow *)configureSheet {
    if(!TARadar.licenseAccepted){NSPanel *notice=[[NSPanel alloc] initWithContentRect:NSMakeRect(0,0,520,100) styleMask:NSWindowStyleMaskTitled backing:NSBackingStoreBuffered defer:NO];NSTextField *label=[NSTextField wrappingLabelWithString:@"Launch Threat Atlas SOC.app to review and accept the licence."];label.frame=NSMakeRect(20,30,480,50);[notice.contentView addSubview:label];NSButton *done=[NSButton buttonWithTitle:@"Close" target:self action:@selector(closeOptions:)];done.frame=NSMakeRect(400,5,100,25);[notice.contentView addSubview:done];self.options=notice;return notice;}
    self.options=[[NSPanel alloc] initWithContentRect:NSMakeRect(0,0,560,390) styleMask:NSWindowStyleMaskTitled backing:NSBackingStoreBuffered defer:NO];
    self.options.title=@"Threat Atlas · Radar alpha settings";
    NSTextField *text=[NSTextField wrappingLabelWithString:@"Cloudflare Radar: optional aggregated traffic and outage layers.\nCC BY-NC 4.0: noncommercial evaluation only unless separately authorized.\nAPI token permission: Account > Radar > Read. Stored in macOS Keychain.\nExisting token is retained when the field is left empty.\nProvider freshness is separate from GreyNoise. No Windows/Linux change."];
    text.frame=NSMakeRect(20,235,520,135);[self.options.contentView addSubview:text];
    NSArray *keys=@[@"TARadarEnabled",@"TARadarOutages",@"TARadarTraffic"];
    NSArray *titles=@[@"Enable Radar (noncommercial evaluation)",@"Show outage layer",@"Show traffic trend layer"];
    for(NSUInteger i=0;i<keys.count;i++){NSButton *button=[NSButton checkboxWithTitle:titles[i] target:self action:@selector(toggleRadar:)];button.identifier=keys[i];button.state=[TARadar.defaults boolForKey:keys[i]]?NSControlStateValueOn:NSControlStateValueOff;button.frame=NSMakeRect(20,205-i*32,520,28);[self.options.contentView addSubview:button];}
    self.radarToken=[[NSSecureTextField alloc] initWithFrame:NSMakeRect(20,80,360,28)];self.radarToken.placeholderString=@"Radar Read token (optional replacement)";[self.options.contentView addSubview:self.radarToken];
    NSButton *save=[NSButton buttonWithTitle:@"Save / retry" target:self action:@selector(saveRadar:)];save.frame=NSMakeRect(390,80,145,28);[self.options.contentView addSubview:save];
    NSButton *done=[NSButton buttonWithTitle:@"Done" target:self action:@selector(closeOptions:)];done.frame=NSMakeRect(435,20,100,32);[self.options.contentView addSubview:done];return self.options;
}
- (void)closeOptions:(id)sender {[self.options.sheetParent endSheet:self.options];}
@end
