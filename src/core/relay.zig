//! Bidirectional relay with half-close propagation.

const std = @import("std");
const limits = @import("limits.zig");
const Metrics = @import("metrics.zig").Metrics;
const Stream = @import("../transport/stream.zig").Stream;

pub const Error = Stream.ReadError || Stream.WriteError || Stream.ShutdownError;

const Direction = enum { client_to_remote, remote_to_client };

const RelayContext = struct {
    io: std.Io,
    client: Stream,
    remote: Stream,
    metrics: *Metrics,
    client_buffer: []u8,
    remote_buffer: []u8,
};

pub fn relay(io: std.Io, client: Stream, remote: Stream, metrics: *Metrics) Error!void {
    var client_buffer: [limits.relay_buffer_size_default]u8 = undefined;
    var remote_buffer: [limits.relay_buffer_size_default]u8 = undefined;

    var context: RelayContext = .{
        .io = io,
        .client = client,
        .remote = remote,
        .metrics = metrics,
        .client_buffer = client_buffer[0..],
        .remote_buffer = remote_buffer[0..],
    };

    var upstream = io.concurrent(
        copyWrapper,
        .{ &context, Direction.client_to_remote },
    ) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            abortBoth(&context);
            return error.Unexpected;
        },
    };
    const downstream_result = copy(&context, Direction.remote_to_client);

    if (downstream_result) |_| {
        try upstream.await(io);
        return;
    } else |downstream_error| {
        _ = upstream.await(io) catch {};
        return downstream_error;
    }
}

fn copyWrapper(context: *RelayContext, direction: Direction) Error!void {
    return copy(context, direction);
}

fn copy(context: *RelayContext, direction: Direction) Error!void {
    const source, const target = switch (direction) {
        .client_to_remote => .{ context.client, context.remote },
        .remote_to_client => .{ context.remote, context.client },
    };
    const buffer = switch (direction) {
        .client_to_remote => context.client_buffer,
        .remote_to_client => context.remote_buffer,
    };

    while (true) {
        var buffers = [_][]u8{buffer};
        const read_len = source.read(context.io, &buffers) catch |err| {
            abortBoth(context);
            return err;
        };
        if (read_len == 0) break;

        _ = target.write(context.io, &.{buffer[0..read_len]}) catch |err| {
            abortBoth(context);
            return err;
        };

        switch (direction) {
            .client_to_remote => context.metrics.addToRemote(read_len),
            .remote_to_client => context.metrics.addToClient(read_len),
        }
    }

    target.shutdown(context.io, .send) catch |err| switch (err) {
        error.NotConnected => {},
        else => {
            abortBoth(context);
            return err;
        },
    };
}

fn abortBoth(context: *RelayContext) void {
    context.client.shutdown(context.io, .both) catch {};
    context.remote.shutdown(context.io, .both) catch {};
}
