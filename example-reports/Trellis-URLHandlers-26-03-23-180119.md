## URL Handler Analysis Report

**Binary**: DVIA-v2
**Generated**: 2026-03-23 18:01:19
**Total Handlers Found**: 73

---

### Summary by Type

| Type | Count | Description |
|------|-------|-------------|
| swiftui | 17 | SwiftUI .onOpenURL handlers |
| uikit | 0 | UIKit delegate methods |
| appdelegate | 0 | AppDelegate/SceneDelegate handlers |
| custom | 50 | Custom URL handling functions |

### Summary by Confidence

| Confidence | Count |
|------------|-------|
| high | 15 |
| medium | 16 |
| low | 42 |

---

### Detected Handlers

#### HIGH Confidence

| Address | Type | Symbol |
|---------|------|--------|
| `0x100153edc` | swiftui | `$$protocol_witness_for_Swift._ObjectiveCBridgeable._bridgeTo...` |
| `0x100153f14` | swiftui | `$$protocol_witness_for_static_Swift._ObjectiveCBridgeable._f...` |
| `0x100153f5c` | swiftui | `$$protocol_witness_for_static_Swift._ObjectiveCBridgeable._c...` |
| `0x100153fa8` | swiftui | `$$protocol_witness_for_static_Swift._ObjectiveCBridgeable._u...` |
| `0x100153ff0` | swiftui | `$$protocol_witness_for_Swift.Hashable.hashValue.getter_:_Swi...` |
| `0x10015402c` | swiftui | `$$protocol_witness_for_Swift.Hashable.hash(into:_inout_Swift...` |
| `0x100154070` | swiftui | `$$protocol_witness_for_Swift.Hashable._rawHashValue(seed:_Sw...` |
| `0x1001542d4` | swiftui | `$$protocol_witness_for_static_Swift.Equatable.==_infix(A,A)_...` |
| `0x1001544c4` | swiftui | `$$protocol_witness_for_Swift.RawRepresentable.init(rawValue:...` |
| `0x1001544f8` | swiftui | `$$__C.UIApplicationOpenURLOptionsKey.init(rawValue:_Swift.St...` |
| `0x100154560` | swiftui | `$$protocol_witness_for_Swift.RawRepresentable.rawValue.gette...` |
| `0x1001545dc` | swiftui | `$$protocol_witness_for_Swift._HasCustomAnyHashableRepresenta...` |
| `0x100154624` | swiftui | `$$base_witness_table_accessor_for_Swift.RawRepresentable_in_...` |
| `0x1001546a8` | swiftui | `$$base_witness_table_accessor_for_Swift._HasCustomAnyHashabl...` |
| `0x10015472c` | swiftui | `$$base_witness_table_accessor_for_Swift.Equatable_in___C.UIA...` |

#### MEDIUM Confidence

| Address | Type | Symbol |
|---------|------|--------|
| `0x100152f94` | swiftui | `application:openURL:options:` |
| `0x10016fa1c` | custom | `$URLSchemeButtonTapped` |
| `0x10016fa7c` | custom | `URLSchemeButtonTapped:` |
| `0x1002e374c` | custom | `withSessionDeeplink:` |
| `0x1002e3dd4` | custom | `originDeeplink` |
| `0x1002e3ddc` | custom | `setOriginDeeplink:` |
| `0x100310010` | custom | `addSessionOrigin:withDeepLink:` |
| `0x10031176c` | custom | `setSessionOrigin:deeplink:` |
| `0x10031b468` | custom | `setOrigin:withDeepLink:` |
| `0x10031b52c` | custom | `___52-[FlurrySessionOriginSource_setOrigin:withDeepLink:]_bl...` |
| `0x10031b544` | custom | `onqueue_setOrigin:withDeepLink:` |
| `0x1003297d8` | custom | `initWithOrigin:deeplink:` |
| `0x100329880` | custom | `sessionOriginWithOrigin:deeplink:` |
| `0x100329cd0` | custom | `deeplink` |
| `0x100329ce0` | custom | `setDeeplink:` |
| `0x10036f984` | swiftui | `_objc_msgSend$canOpenURL:` |

#### LOW Confidence

| Address | Type | Symbol |
|---------|------|--------|
| `0x100172380` | custom | `$$protocol_witness_for_Swift._ObjectiveCBridgeable._bridgeTo...` |
| `0x1001723b8` | custom | `$$protocol_witness_for_static_Swift._ObjectiveCBridgeable._f...` |
| `0x100172400` | custom | `$$protocol_witness_for_static_Swift._ObjectiveCBridgeable._c...` |
| `0x10017244c` | custom | `$$protocol_witness_for_static_Swift._ObjectiveCBridgeable._u...` |
| `0x100172494` | custom | `$$protocol_witness_for_Swift.Hashable.hashValue.getter_:_Swi...` |
| `0x1001724d0` | custom | `$$protocol_witness_for_Swift.Hashable.hash(into:_inout_Swift...` |
| `0x100172514` | custom | `$$protocol_witness_for_Swift.Hashable._rawHashValue(seed:_Sw...` |
| `0x100172558` | custom | `$$protocol_witness_for_static_Swift.Equatable.==_infix(A,A)_...` |
| `0x1001725a0` | custom | `$$protocol_witness_for_Swift.RawRepresentable.init(rawValue:...` |
| `0x1001725d4` | custom | `$$__C.UIApplicationOpenExternalURLOptionsKey.init(rawValue:_...` |
| `0x10017263c` | custom | `$$protocol_witness_for_Swift.RawRepresentable.rawValue.gette...` |
| `0x1001726b8` | custom | `$$protocol_witness_for_Swift._HasCustomAnyHashableRepresenta...` |
| `0x100172cc8` | custom | `$$base_witness_table_accessor_for_Swift.RawRepresentable_in_...` |
| `0x100172d4c` | custom | `$$base_witness_table_accessor_for_Swift._HasCustomAnyHashabl...` |
| `0x100172dd0` | custom | `$$base_witness_table_accessor_for_Swift.Equatable_in___C.UIA...` |
| `0x1001bf918` | custom | `___69-[CBLOpenIDConnectAuthorizer_continueAsyncLoginWithURL:...` |
| `0x1001bf9c4` | custom | `___69-[CBLOpenIDConnectAuthorizer_continueAsyncLoginWithURL:...` |
| `0x1001cc37c` | custom | `openForURLRequest:` |
| `0x1001f0298` | custom | `URLSession:task:willPerformHTTPRedirection:newRequest:comple...` |
| `0x1001f03b0` | custom | `___92-[CBLRemoteSession_URLSession:task:willPerformHTTPRedir...` |
| `0x1001f046c` | custom | `URLSession:task:didReceiveChallenge:completionHandler:` |
| `0x1001f055c` | custom | `___74-[CBLRemoteSession_URLSession:task:didReceiveChallenge:...` |
| `0x1001f08f8` | custom | `URLSession:dataTask:didReceiveResponse:completionHandler:` |
| `0x1001f09ec` | custom | `___77-[CBLRemoteSession_URLSession:dataTask:didReceiveRespon...` |
| `0x1001f0b78` | unknown | `URLSession:dataTask:didReceiveData:` |
| `0x1001f0c28` | unknown | `___55-[CBLRemoteSession_URLSession:dataTask:didReceiveData:]...` |
| `0x1001f0ee0` | custom | `URLSession:dataTask:willCacheResponse:completionHandler:` |
| `0x100241e18` | unknown | `initWithWebSocket:transportQueue:URL:incoming:` |
| `0x1002972fc` | custom | `handlesURL:` |
| `0x1002d7d9c` | custom | `URLSession:didReceiveChallenge:completionHandler:` |
| `0x1002d7fac` | custom | `URLSession:dataTask:didReceiveResponse:completionHandler:` |
| `0x1002d8214` | unknown | `URLSession:dataTask:didReceiveData:` |
| `0x1002d8330` | custom | `URLSession:dataTask:willCacheResponse:completionHandler:` |
| `0x1002d8598` | custom | `URLSession:task:didReceiveChallenge:completionHandler:` |
| `0x1002d8a5c` | custom | `URLSession:task:willPerformHTTPRedirection:newRequest:comple...` |
| `0x1002d9238` | unknown | `URLSession:betterRouteDiscoveredForStreamTask:` |
| `0x1002fe37c` | unknown | `URLSession:dataTask:didReceiveData:` |
| `0x1002fe668` | custom | `URLSession:task:willPerformHTTPRedirection:newRequest:comple...` |
| `0x100304150` | custom | `submitURLWithCompletionHandler:` |
| `0x100304344` | custom | `___49-[FlurryGDPRUtil_submitURLWithCompletionHandler:]_block...` |
| `0x10032a7c4` | custom | `handleDownloadedData:withURLSession:withDownloadTask:` |
| `0x10032a890` | custom | `___79-[FConfigRemoteAPIClient_handleDownloadedData:withURLSe...` |

---

### Analysis Notes

**SwiftUI Reactive Architecture**:
- URL handlers in SwiftUI apps update state, then return
- Traditional backtrace analysis will NOT show the handler on the call stack
- Use symbol-based detection (this report) for SwiftUI apps

**Recommended Next Steps**:
1. Open handlers in Ghidra for static analysis
2. Use generated Frida script for runtime monitoring
3. Test URL schemes to trigger handlers and observe behavior



### UI Entry Points Detected (144)

| Address | Type | Class | Symbol |
|---------|------|-------|--------|
| `0x10013545c` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100135690` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1001374ac` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100137a90` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10013d988` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10013dd30` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10013fea0` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100140248` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100145960` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100145a68` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100147554` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10014765c` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100149998` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100149dcc` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10014a79c` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10014a8a4` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10014b50c` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10014b62c` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10014e170` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10014e278` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10014f370` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10014f478` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1001518c8` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100151d68` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100155218` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1001555f4` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100156590` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10015684c` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1001577bc` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100157b64` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10015a4c0` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10015adac` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10015fea0` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10015ff20` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100162cf8` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10016338c` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1001657d0` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100165b20` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10016a360` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10016a468` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10016af78` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10016b108` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10016cf34` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10016d03c` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10016f8d8` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10016f9e0` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10017333c` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10017368c` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100173ec4` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100174214` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100174e14` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100174f1c` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100176028` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100176130` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100177438` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1001777e0` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100178668` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100178a10` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10017a128` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10017a230` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10017af04` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10017b2ac` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10017c488` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10017c7bc` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10017ebe8` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10017ef90` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10017f7c8` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10017f8d0` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1001800ec` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1001801f4` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100182358` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1001823d8` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100186328` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1001868a4` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10018a098` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10018a118` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10018ce9c` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10018cfe8` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100191710` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100191818` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100193560` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100193908` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100195410` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1001957b8` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1001971a8` | viewDidLoad | `—` | `viewDidLoad` |
| `0x100197228` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1001991e4` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10019958c` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10019a7d8` | viewDidLoad | `—` | `viewDidLoad` |
| `0x10019add8` | viewDidLoad | `—` | `viewDidLoad` |
| `0x1002f00f0` | viewDidLoad | `—` | `-[UIViewController(FlurryScreenTimeMonitor)_fl_swi...` |
| `0x10003d78c` | swiftui_observer | `—` | `getSectionChanges:rowChanges:forNotifications:with...` |
| `0x10003e1c8` | swiftui_observer | `—` | `___88-[YapDatabaseViewConnection_getSectionChanges...` |
| `0x1000fe508` | swiftui_observer | `—` | `preProcessChanges:withOriginalMappings:finalMappin...` |
| `0x100100f18` | swiftui_observer | `—` | `consolidateSectionChanges:` |
| `0x100105230` | swiftui_observer | `—` | `postProcessAndFilterSectionChanges:withOriginalMap...` |
| `0x100105a44` | swiftui_observer | `—` | `getSectionChanges:rowChanges:withOriginalMappings:...` |
| `0x1001d63ec` | swiftui_observer | `—` | `onChange` |
| `0x1001d63fc` | swiftui_observer | `—` | `setOnChange:` |
| `0x100291fe0` | swiftui_observer | `—` | `replicationChanged:` |
| `0x10036fe84` | swiftui_observer | `—` | `_objc_msgSend$consolidateSectionChanges:` |
| `0x1003724c4` | swiftui_observer | `—` | `_objc_msgSend$getSectionChanges:rowChanges:withOri...` |
| `0x100375424` | swiftui_observer | `—` | `_objc_msgSend$postProcessAndFilterSectionChanges:w...` |
| `0x1003755a4` | swiftui_observer | `—` | `_objc_msgSend$preProcessChanges:withOriginalMappin...` |
| `0x100137acc` | viewWillAppear | `—` | `viewWillAppear` |
| `0x100137ba0` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x10013dd6c` | viewWillAppear | `—` | `viewWillAppear` |
| `0x10013de40` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x100140284` | viewWillAppear | `—` | `viewWillAppear` |
| `0x100140358` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x100149e08` | viewWillAppear | `—` | `viewWillAppear` |
| `0x100149edc` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x100155630` | viewWillAppear | `—` | `viewWillAppear` |
| `0x100155704` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x100156888` | viewWillAppear | `—` | `viewWillAppear` |
| `0x10015695c` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x100157d34` | viewWillAppear | `—` | `viewWillAppear` |
| `0x100157e08` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x100165bf4` | viewWillAppear | `—` | `viewWillAppear` |
| `0x100165cc8` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x1001736c8` | viewWillAppear | `—` | `viewWillAppear` |
| `0x10017379c` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x100174250` | viewWillAppear | `—` | `viewWillAppear` |
| `0x100174324` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x1001778b4` | viewWillAppear | `—` | `viewWillAppear` |
| `0x100177988` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x100178be0` | viewWillAppear | `—` | `viewWillAppear` |
| `0x100178cb4` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x10017b47c` | viewWillAppear | `—` | `viewWillAppear` |
| `0x10017b550` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x10017efcc` | viewWillAppear | `—` | `viewWillAppear` |
| `0x10017f0a0` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x1001868e0` | viewWillAppear | `—` | `viewWillAppear` |
| `0x1001869b4` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x100193944` | viewWillAppear | `—` | `viewWillAppear` |
| `0x100193a18` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x1001957f4` | viewWillAppear | `—` | `viewWillAppear` |
| `0x1001958c8` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x1001995c8` | viewWillAppear | `—` | `viewWillAppear` |
| `0x10019969c` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x10019ae14` | viewWillAppear | `—` | `viewWillAppear` |
| `0x10019aee8` | viewWillAppear | `—` | `viewWillAppear:` |
| `0x1002f01e8` | viewDidAppear | `—` | `-[UIViewController(FlurryScreenTimeMonitor)_fl_swi...` |
| `0x1003651a0` | viewDidAppear | `—` | `viewDidAppear:` |

