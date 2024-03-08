const std = @import("std");

fn HashLengthExtender(
    comptime Hash: type,
    comptime endian: std.builtin.Endian,
    comptime PaddingLengthField: type,
) type {
    return struct {
        const Self = @This();

        pub const Hasher = Hash;

        pub fn genState(hash: [Hash.digest_length]u8) !std.meta.FieldType(Hash, .s) {
            var state: std.meta.FieldType(Hash, .s) = undefined;

            const StateChild = std.meta.Child(std.meta.FieldType(Hash, .s));

            inline for (0..state.len) |i| {
                state[i] = std.mem.readInt(
                    StateChild,
                    hash[i * @sizeOf(StateChild) .. i * @sizeOf(StateChild) + @sizeOf(StateChild)],
                    endian,
                );
            }

            return state;
        }

        pub const ExtensionResult = struct {
            data: []const u8,
            hash: [Hash.digest_length]u8,
        };

        pub fn extend(
            allocator: std.mem.Allocator,
            orig_data: []const u8,
            new_data: []const u8,
            salt_len: usize,
            orig_hash: [Hash.digest_length]u8,
        ) !ExtensionResult {
            var h = Hash.init(.{});

            // ensure that the full hash internal state is valid
            for (0..std.mem.alignForward(usize, salt_len + orig_data.len, Hash.block_length)) |_| {
                h.update(&[_]u8{'A'});
            }

            // set internal state to that of the original hash
            h.s = try Self.genState(orig_hash);

            h.update(new_data);

            var out: [Hash.digest_length]u8 = undefined;
            h.final(out[0..]);

            var result = ExtensionResult{
                .data = undefined,
                .hash = out,
            };

            var data = std.ArrayList(u8).init(allocator);
            errdefer data.deinit();

            try data.appendSlice(orig_data);
            try data.append(0x80);

            try data.appendNTimes(0, Hash.block_length - (data.items.len + salt_len) % Hash.block_length - @sizeOf(PaddingLengthField));
            try data.writer().writeInt(PaddingLengthField, (orig_data.len + salt_len) * 8, endian);

            try data.appendSlice(new_data);

            result.data = try data.toOwnedSlice();
            return result;
        }
    };
}

pub const Md5 = HashLengthExtender(std.crypto.hash.Md5, .Little, u64);
pub const Sha1 = HashLengthExtender(std.crypto.hash.Sha1, .Big, u64);
pub const Sha256 = HashLengthExtender(std.crypto.hash.sha2.Sha256, .Big, u64);
pub const Sha512 = HashLengthExtender(std.crypto.hash.sha2.Sha512, .Big, u128);

fn testExtendSingle(comptime Extender: type, salt: []const u8, data: []const u8, added: []const u8) !void {
    const allocator = std.testing.allocator;

    var orig_hash: [Extender.Hasher.digest_length]u8 = undefined;

    // simulate server generating hash with valid input and known salt
    var h = Extender.Hasher.init(.{});
    h.update(salt);
    h.update(data);
    h.final(orig_hash[0..]);

    // run hash extender
    const result = try Extender.extend(allocator, data, added, salt.len, orig_hash);
    defer allocator.free(result.data);

    // simulate server verifying new data + hash
    h = Extender.Hasher.init(.{});
    var new_hash: [Extender.Hasher.digest_length]u8 = undefined;

    const full_data = try std.mem.concat(allocator, u8, &[_][]const u8{ salt, result.data });
    defer allocator.free(full_data);

    h.update(full_data);
    h.final(new_hash[0..]);

    try std.testing.expectEqual(result.hash, new_hash);
}

fn testExtend(comptime Extender: type) !void {
    const block_length = Extender.Hasher.block_length;

    try testExtendSingle(Extender, "secret", "data", "added");

    try testExtendSingle(Extender, &[_]u8{'A'} ** (block_length + 1), "data", "added");
    try testExtendSingle(Extender, "salt", &[_]u8{'A'} ** (block_length + 1), "added");
    try testExtendSingle(Extender, "salt", "data", &[_]u8{'A'} ** (block_length + 1));

    try testExtendSingle(Extender, &[_]u8{'A'} ** (block_length + 1), &[_]u8{'A'} ** (block_length + 1), "added");
    try testExtendSingle(Extender, &[_]u8{'A'} ** (block_length + 1), "data", &[_]u8{'A'} ** (block_length + 1));
    try testExtendSingle(Extender, "salt", &[_]u8{'A'} ** (block_length + 1), &[_]u8{'A'} ** (block_length + 1));

    try testExtendSingle(Extender, &[_]u8{'A'} ** (block_length + 1), &[_]u8{'A'} ** (block_length + 1), &[_]u8{'A'} ** (block_length + 1));
}

test "extend md5" {
    try testExtend(Md5);
}

test "extend Sha1" {
    try testExtend(Sha1);
}

test "extend Sha256" {
    try testExtend(Sha256);
}

test "extend Sha512" {
    try testExtend(Sha512);
}
