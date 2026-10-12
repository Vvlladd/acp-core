import Foundation

@main
enum Entry {
    static func main() {
        do {
            if CommandLine.arguments == [CommandLine.arguments[0], "--version"] {
                print(Analyzer.version)
                return
            }
            guard CommandLine.arguments.count == 1 else { throw InputError.invalid }
            var bytes = Data()
            while let part = try FileHandle.standardInput.read(upToCount: 65536), !part.isEmpty {
                guard bytes.count + part.count <= 48 * 1024 * 1024 else { throw InputError.invalid }
                bytes.append(part)
            }
            let input = try JSONDecoder().decode(ReviewInput.self, from: bytes)
            guard input.version == 1, input.files.count <= 2000,
                  input.files.allSatisfy({ $0.path.utf8.count <= 1024 && $0.source.utf8.count <= 2 * 1024 * 1024 }),
                  input.files.reduce(0, { $0 + $1.source.utf8.count }) <= 32 * 1024 * 1024 else { throw InputError.invalid }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let output = try encoder.encode(Analyzer.review(input))
            guard output.count <= 4 * 1024 * 1024 else { throw InputError.invalid }
            try FileHandle.standardOutput.write(contentsOf: output)
        } catch {
            try? FileHandle.standardError.write(contentsOf: Data("Swift Review could not analyze this input.\n".utf8))
            exit(1)
        }
    }
    enum InputError: Error { case invalid }
}
