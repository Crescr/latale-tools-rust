fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let mut resource = winresource::WindowsResource::new();
    resource
        .set("CompanyName", "元气君")
        .set("FileDescription", "LaTale Tools 命令行工具")
        .set("ProductName", "LaTale Tools CLI")
        .set("LegalCopyright", "Copyright © 元气君")
        .set("Comments", "提需求和 Bug：QQ: 915994204");
    resource
        .compile()
        .expect("failed to compile Windows version metadata");
}
