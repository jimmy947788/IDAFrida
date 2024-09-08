

const MODULE_NAME="libapp.so";
let isFoudModule = false;
let isHooked = false;

// @ts-ignore
function print_arg(addr) {
    try {
        var module = Process.findRangeByAddress(addr);
        if (module != null) return "\n"+hexdump(addr) + "\n";
        return ptr(addr) + "\n";
    } catch (e) {
        return addr + "\n";
    }
}

// @ts-ignore
function hook_native_addr(module, offset, funcName, paramsNum) {
    try {
        const funcPtr = module.base.add(offset);
        console.log("offset:", offset)
        console.log("funcPtr:", funcPtr);
        console.log("funcName:", funcName);
        console.log("paramsNum:", paramsNum);

        Interceptor.attach(funcPtr, {
            onEnter: function (args) {
                this.logs = "";
                this.params = [];
                // @ts-ignore
                this.logs=this.logs.concat("So: " + module.name + "  Method: " + funcName + " offset: " + offset + "\n");
                for (let i = 0; i < paramsNum; i++) {
                    this.params.push(args[i]);
                    this.logs=this.logs.concat("this.args" + i + " onEnter: " + print_arg(args[i]));
                }
            }, onLeave: function (retval) {
                for (let i = 0; i < paramsNum; i++) {
                    this.logs=this.logs.concat("this.args" + i + " onLeave: " + print_arg(this.params[i]));
                }
                this.logs=this.logs.concat("retval onLeave: " + print_arg(retval) + "\n");
                console.log(this.logs);
            }
        });
    } catch (e) {
        console.log(e);
    }
}

//hook_dlopen
function hook_dlopen(dlopenPtr) {
    Interceptor.attach(dlopenPtr, {
        onEnter: function (args) {
            if (args[0].isNull()) return

            let moduleFullPath = args[0].readCString()
            console.log('dlopen:', moduleFullPath);
            
            if(moduleFullPath == MODULE_NAME || moduleFullPath.includes(MODULE_NAME) &&
                !isFoudModule){
                isFoudModule = true;
                console.warn("foud targe module:", moduleFullPath);
            }
            // if (moduleFullPath.includes(MODULE_NAME) && !isFoudModule) {
            //     isFoudModule = true;
            // }

        },
        onLeave: function (retval) {
            
            console.warn(`isFoudModule=${isFoudModule}, isHooked=${isHooked}`);
            if(isFoudModule && !isHooked){
                isHooked = true;

                var m = Process.findModuleByName(MODULE_NAME); 
                console.error(`module: ${m.name}, addr: ${m.base}, size: ${m.size}, path: ${m.path}`);
                
                // hook native function append here
                hook_native_addr(m, ptr(0x1089C8), "getFunctionPointerBasedOnCondition_1089c8", 0x1);
            }
        },
    })
}
setImmediate(function() {
    let dlopenPtr = Module.findExportByName('libdl.so', 'dlopen')
    console.log('dlopen', dlopenPtr);

    let dlopenExPtr = Module.findExportByName('libdl.so', 'android_dlopen_ext')
    console.log('dlopenExPtr', dlopenExPtr);

    hook_dlopen(dlopenPtr)
    hook_dlopen(dlopenExPtr);
});


