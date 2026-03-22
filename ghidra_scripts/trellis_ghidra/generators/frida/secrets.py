from .base import combine_hooks

def generate_secrets_script(binary_name: str = "(auto-detected)") -> str:
    """
    Generate Frida script for secret detection hooks.
    This script hooks Base64/Hex decode functions and sensitive sinks.
    """
    hooks = []
    
    # 1. Base64 Decode Hook
    hooks.append("""
    // Monitor Base64 Decoding (NSData)
    hookObjCMethod('NSData', '- initWithBase64EncodedString:options:', function(impl) {
        Interceptor.attach(impl, {
            onEnter: function(args) {
                var str = new ObjC.Object(args[2]);
                this.input = str.toString();
            },
            onLeave: function(retval) {
                if (this.input) {
                    var decoded = new ObjC.Object(retval);
                    console.log('[!] Base64 Decode Detected');
                    console.log('    Input:  ' + this.input.substring(0, 50) + '...');
                    console.log('    Output: ' + decoded.description());
                }
            }
        });
    });
    """)
    
    # 2. CCCrypt Hook
    hooks.append("""
    // Monitor CCCrypt Keys
    var CCCrypt = findExport('CCCrypt', 'libcommonCrypto');
    if (CCCrypt) {
        Interceptor.attach(CCCrypt, {
            onEnter: function(args) {
                var op = args[0].toInt32();
                var keyLen = args[4].toInt32();
                var key = args[3];
                
                console.log('[*] CCCrypt Call');
                console.log('    Op: ' + (op === 0 ? 'Encrypt' : 'Decrypt'));
                console.log('    Key: ' + trellisHexdump(key, Math.min(keyLen, 32)));
            }
        });
    }
    """)

    return combine_hooks(hooks, "secrets", binary_name, use_lazy_loading=False)