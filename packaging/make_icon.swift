#!/usr/bin/swift
// HopHarbor's original geometric app icon. Requires macOS AppKit and iconutil.
// Usage: swift packaging/make_icon.swift [output-directory]
import AppKit
import Foundation

let fileManager = FileManager.default
let sourceDirectory = URL(fileURLWithPath: #filePath).standardizedFileURL.deletingLastPathComponent()
let output = CommandLine.arguments.count > 1
    ? URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true).standardizedFileURL
    : sourceDirectory.appendingPathComponent("assets", isDirectory: true)
let iconset = output.appendingPathComponent("HopHarbor.iconset", isDirectory: true)
try fileManager.createDirectory(at: iconset, withIntermediateDirectories: true)

func color(_ hex: UInt32, alpha: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 255) / 255,
            green: CGFloat((hex >> 8) & 255) / 255,
            blue: CGFloat(hex & 255) / 255, alpha: alpha)
}

func render(_ size: Int, to destination: URL) throws {
    guard let bitmap = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
        isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
    ), let graphics = NSGraphicsContext(bitmapImageRep: bitmap) else {
        throw NSError(domain: "HopHarborIcon", code: 1,
                      userInfo: [NSLocalizedDescriptionKey: "Could not create the icon canvas."])
    }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = graphics
    let context = graphics.cgContext
    context.scaleBy(x: CGFloat(size) / 1024, y: CGFloat(size) / 1024)
    context.translateBy(x: 0, y: 1024)
    context.scaleBy(x: 1, y: -1)
    context.setShouldAntialias(true)
    context.setAllowsAntialiasing(true)

    let tile = CGPath(roundedRect: CGRect(x: 72, y: 72, width: 880, height: 880),
                      cornerWidth: 198, cornerHeight: 198, transform: nil)
    context.saveGState()
    if size >= 64 {
        context.setShadow(offset: CGSize(width: 0, height: 15), blur: 27,
                          color: color(0x071E32, alpha: 0.28))
    }
    context.addPath(tile)
    context.setFillColor(color(0x0C6277))
    context.fillPath()
    context.restoreGState()

    context.saveGState()
    context.addPath(tile)
    context.clip()
    let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(),
                              colors: [color(0x168F98), color(0x0B647A), color(0x102E50)] as CFArray,
                              locations: [0, 0.48, 1])!
    context.drawLinearGradient(gradient, start: CGPoint(x: 120, y: 96),
                               end: CGPoint(x: 904, y: 952), options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
    let glow = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(),
                          colors: [color(0x8EF3D6, alpha: 0.19), color(0x8EF3D6, alpha: 0)] as CFArray,
                          locations: [0, 1])!
    context.drawRadialGradient(glow, startCenter: CGPoint(x: 210, y: 130), startRadius: 0,
                               endCenter: CGPoint(x: 210, y: 130), endRadius: 720,
                               options: .drawsAfterEndLocation)
    context.restoreGState()

    context.addPath(CGPath(roundedRect: CGRect(x: 73.5, y: 73.5, width: 877, height: 877),
                           cornerWidth: 196.5, cornerHeight: 196.5, transform: nil))
    context.setStrokeColor(color(0xE5FFF8, alpha: 0.15))
    context.setLineWidth(3)
    context.strokePath()

    // Two piers, four endpoint nodes and an arched connection form a compact H.
    context.setStrokeColor(color(0xF4FDFB))
    context.setFillColor(color(0xF4FDFB))
    context.setLineCap(.round)
    context.setLineJoin(.round)
    context.setLineWidth(78)
    for x in [CGFloat(320), CGFloat(704)] {
        context.move(to: CGPoint(x: x, y: 316))
        context.addLine(to: CGPoint(x: x, y: 708))
        context.strokePath()
    }
    context.setLineWidth(72)
    context.move(to: CGPoint(x: 320, y: 550))
    context.addCurve(to: CGPoint(x: 704, y: 550),
                     control1: CGPoint(x: 420, y: 430), control2: CGPoint(x: 604, y: 430))
    context.strokePath()
    for x in [CGFloat(320), CGFloat(704)] {
        for y in [CGFloat(316), CGFloat(708)] {
            context.fillEllipse(in: CGRect(x: x - 54, y: y - 54, width: 108, height: 108))
        }
    }

    context.flush()
    NSGraphicsContext.restoreGraphicsState()
    guard let data = bitmap.representation(using: .png, properties: [:]) else {
        throw NSError(domain: "HopHarborIcon", code: 2,
                      userInfo: [NSLocalizedDescriptionKey: "Could not encode the icon PNG."])
    }
    try data.write(to: destination, options: .atomic)
}

// This editable vector master uses the same 1024-unit drawing coordinates.
let svg = """
<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024" role="img" aria-labelledby="title desc">
  <title id="title">HopHarbor app icon</title>
  <desc id="desc">A white H made from two connected piers and four network nodes on a teal and navy rounded tile.</desc>
  <defs>
    <linearGradient id="tile" x1="120" y1="96" x2="904" y2="952" gradientUnits="userSpaceOnUse">
      <stop stop-color="#168F98"/><stop offset=".48" stop-color="#0B647A"/><stop offset="1" stop-color="#102E50"/>
    </linearGradient>
    <radialGradient id="glow" cx="210" cy="130" r="720" gradientUnits="userSpaceOnUse">
      <stop stop-color="#8EF3D6" stop-opacity=".19"/><stop offset="1" stop-color="#8EF3D6" stop-opacity="0"/>
    </radialGradient>
    <filter id="shadow" x="-15%" y="-15%" width="130%" height="135%" color-interpolation-filters="sRGB">
      <feDropShadow dx="0" dy="15" stdDeviation="13.5" flood-color="#071E32" flood-opacity=".28"/>
    </filter>
  </defs>
  <rect x="72" y="72" width="880" height="880" rx="198" fill="url(#tile)" filter="url(#shadow)"/>
  <rect x="72" y="72" width="880" height="880" rx="198" fill="url(#glow)"/>
  <rect x="73.5" y="73.5" width="877" height="877" rx="196.5" fill="none" stroke="#E5FFF8" stroke-opacity=".15" stroke-width="3"/>
  <g stroke="#F4FDFB" fill="#F4FDFB" stroke-linecap="round" stroke-linejoin="round">
    <path d="M320 316V708M704 316V708" fill="none" stroke-width="78"/>
    <path d="M320 550C420 430 604 430 704 550" fill="none" stroke-width="72"/>
    <g stroke="none"><circle cx="320" cy="316" r="54"/><circle cx="320" cy="708" r="54"/><circle cx="704" cy="316" r="54"/><circle cx="704" cy="708" r="54"/></g>
  </g>
</svg>
"""
try svg.write(to: output.appendingPathComponent("HopHarbor.svg"), atomically: true, encoding: .utf8)
try render(1024, to: output.appendingPathComponent("HopHarbor-1024.png"))

let sizes: [(String, Int)] = [
    ("icon_16x16.png", 16), ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32), ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128), ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256), ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512), ("icon_512x512@2x.png", 1024)
]
for (name, size) in sizes { try render(size, to: iconset.appendingPathComponent(name)) }

let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", "-o", output.appendingPathComponent("HopHarbor.icns").path, iconset.path]
try iconutil.run()
iconutil.waitUntilExit()
guard iconutil.terminationStatus == 0 else {
    throw NSError(domain: "HopHarborIcon", code: Int(iconutil.terminationStatus),
                  userInfo: [NSLocalizedDescriptionKey: "iconutil could not package the icon."])
}
print("Created HopHarbor.svg, HopHarbor-1024.png, HopHarbor.iconset and HopHarbor.icns in \(output.path)")
