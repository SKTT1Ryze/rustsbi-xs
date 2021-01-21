# rustsbi-xs
香山处理核仿真环境的 `RustSBI` 实现。  
`RustSBI` 是基于 `rustlang` 写的一个 `RISC-V SBI` 实现，具体请看[这里](https://github.com/luojia65/rustsbi)。  
该项目尝试为 `RustSBI` 兼容[香山](https://github.com/RISCVERS/XiangShan)处理核平台。  

## Build
```bash
cargo build
```

## Run
需要：  
+ 香山处理核开发 `verilator` 仿真环境
+ `Rust` 环境
+ `Just` 工具

第一项为香山开发团队独享。  
后两项请看[这里](https://github.com/SKTT1Ryze/rust-xs-evaluation/blob/main/doc/build.md)。  

```bash
just run
```

## Run OS
写这个 `rustsbi-xs` 的同时还写了一个简单的内核用于测试，叫做 `xs-core`，具体请看[这里](https://github.com/SKTT1Ryze/rust-xs-evaluation/tree/main/xs-core)。  

## TODO
更多的调试和完善。  

