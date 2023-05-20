import os
import sys

def replace_in_file(file_path, old_text, new_text):
    
    with open(file_path, 'r', encoding='utf-8') as file:
        filedata = file.read()

    if old_text in filedata:
        print(f"{file_path}: modified")
    else:
        print(f"{file_path}: no changes")
    # Replace the target string
    filedata = filedata.replace(old_text, new_text)
    # Write the file out again
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(filedata)

# old_block = """pub struct TrackedFeatures {
# """
# new_block = """pub struct TrackedFeatures {
#     #[cfg(feature = "timing")]
#     compute_cycles: u64,
# """

# old_block = """fn update(&mut self, segment: L4Pdu) -> Result<()> {
# """
# new_block = """fn update(&mut self, segment: L4Pdu) -> Result<()> {
#         #[cfg(feature = "timing")]
#         let start_tsc = unsafe { rte_rdtsc() };
# """

# old_block = """self.proto = ipv4.protocol() as i32;
#         Ok(())
# """
# new_block = """self.proto = ipv4.protocol() as i32;
#         #[cfg(feature = "timing")]
#         {
#             self.compute_cycles += unsafe { rte_rdtsc() } - start_tsc;
#         }
#         Ok(())
# """

# old_block = """fn extract_features(&self) -> Vec<f32> {
# """
# new_block = """fn extract_features(&mut self) -> Vec<f32> {
#         #[cfg(feature = "timing")]
#         let start_tsc = unsafe { rte_rdtsc() };
# """

# old_block = """features
#     }
# """
# new_block = """#[cfg(feature = "timing")]
#         {
#         self.compute_cycles += unsafe { rte_rdtsc() } - start_tsc;
#         }
#         features
#     }
# """

# old_block = """TrackedFeatures {
#             // sni: String::new(),
# """
# new_block = """TrackedFeatures {
#             #[cfg(feature = "timing")]
#             compute_cycles: 0,
#             // sni: String::new(),
# """

old_block = """subscription.invoke(conn);
"""
new_block = """tsc_record!(subscription.timers, "compute_cycles", self.compute_cycles);
        subscription.invoke(conn);
"""

if len(sys.argv) != 2:
    print("Usage: python script.py <directory>")
    sys.exit(1)

directory = sys.argv[1]
print(directory)

for root, dirs, files in os.walk(directory):
    for file in files:
        if file.endswith(".rs"):  # Modify this line to select the file types you want
            file_path = os.path.join(root, file)
            replace_in_file(file_path, old_block, new_block)
