// Test file for type alias functionality
include "xdp.kh"

type IpAddress = u32
type Port = u16
type EthBuffer = u8[14]

@xdp fn test_type_aliases(ctx: *xdp_md) -> xdp_action {
    var port: Port = 8080
    var ip: IpAddress = 192168001001
    
    return XDP_PASS
}

fn main() -> i32 {
    var prog = load(test_type_aliases)
    attach(prog, "eth0", 0)
    
    print("Type alias demo program attached to eth0")
    print("Demonstrating type alias capabilities...")
    
    // Show type alias functionality
    detach(prog)
    print("Type alias demo program detached")
    
    return 0
} 
