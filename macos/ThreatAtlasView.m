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
@property(nonatomic, strong) NSTextField *bodyText;
@property(nonatomic, strong) NSTextField *languageLabel;
@property(nonatomic, strong) NSPopUpButton *languagePopup;
@property(nonatomic, strong) NSButton *doneButton;
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
        [[self uiString:@"app.starting"] drawAtPoint:NSMakePoint(20,20) withAttributes:@{NSForegroundColorAttributeName:NSColor.whiteColor}];
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
- (NSString *)currentLanguageCode {
    NSUserDefaults *defaults=[ScreenSaverDefaults defaultsForModuleWithName:@"dev.threatatlas.soc.screensaver"] ?: [NSUserDefaults standardUserDefaults];
    return [defaults stringForKey:@"ThreatAtlasUILanguage"] ?: @"en";
}
- (NSString *)uiString:(NSString *)key {
    static NSDictionary *catalog;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSURL *url=[[NSBundle bundleForClass:self.class] URLForResource:@"ui" withExtension:@"json"];
        NSData *data=url ? [NSData dataWithContentsOfURL:url] : nil;
        catalog=data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : @{};
    });
    NSDictionary *language=catalog[[self currentLanguageCode]] ?: catalog[@"en"];
    NSString *value=language[key] ?: catalog[@"en"][key];
    return value ?: key;
}
- (BOOL)hasConfigureSheet {return YES;}
- (NSWindow *)configureSheet {
    self.options=[[NSPanel alloc] initWithContentRect:NSMakeRect(0,0,520,320) styleMask:NSWindowStyleMaskTitled backing:NSBackingStoreBuffered defer:NO];
    self.options.title=[NSString stringWithFormat:@"Threat Atlas SOC %@", [NSBundle bundleForClass:self.class].infoDictionary[@"CFBundleShortVersionString"]];
    self.bodyText=[NSTextField wrappingLabelWithString:[self uiString:@"sheet.body"]];
    self.bodyText.frame=NSMakeRect(20,85,480,215);
    self.bodyText.font=[NSFont systemFontOfSize:11];
    [self.options.contentView addSubview:self.bodyText];
    self.languageLabel=[NSTextField labelWithString:[self uiString:@"sheet.language"]];
    self.languageLabel.frame=NSMakeRect(20,32,80,20);
    [self.options.contentView addSubview:self.languageLabel];
    self.languagePopup=[[NSPopUpButton alloc] initWithFrame:NSMakeRect(100,27,180,26) pullsDown:NO];
    [self.languagePopup addItemsWithTitles:@[@"English",@"Svenska",@"Deutsch",@"Español",@"Italiano"]];
    NSArray *codes=@[@"en",@"sv",@"de",@"es",@"it"];
    NSUInteger index=[codes indexOfObject:[self currentLanguageCode]];
    [self.languagePopup selectItemAtIndex:index==NSNotFound?0:index];
    self.languagePopup.target=self;
    self.languagePopup.action=@selector(languageChanged:);
    [self.options.contentView addSubview:self.languagePopup];
    self.doneButton=[NSButton buttonWithTitle:[self uiString:@"sheet.done"] target:self action:@selector(closeOptions:)];
    self.doneButton.frame=NSMakeRect(405,20,95,32);
    [self.options.contentView addSubview:self.doneButton];
    return self.options;
}
- (void)languageChanged:(NSPopUpButton *)sender {
    NSArray *codes=@[@"en",@"sv",@"de",@"es",@"it"];
    NSInteger index=sender.indexOfSelectedItem;
    if (index < 0 || index >= (NSInteger)codes.count) return;
    NSUserDefaults *defaults=[ScreenSaverDefaults defaultsForModuleWithName:@"dev.threatatlas.soc.screensaver"] ?: [NSUserDefaults standardUserDefaults];
    [defaults setObject:codes[index] forKey:@"ThreatAtlasUILanguage"];
    [defaults synchronize];
    self.bodyText.stringValue=[self uiString:@"sheet.body"];
    self.languageLabel.stringValue=[self uiString:@"sheet.language"];
    self.doneButton.title=[self uiString:@"sheet.done"];
}
- (void)closeOptions:(id)sender {[self.options.sheetParent endSheet:self.options];}
@end
