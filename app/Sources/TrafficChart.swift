import AppKit
import Charts
import SwiftUI

/// 下載 / 上傳的顏色。色盤第 1、2 號，淺色與深色各自驗證過（dataviz validate_palette：全數通過）。
enum TrafficColor {
    static let down = dynamic(light: 0x2A78D6, dark: 0x3987E5)
    static let up = dynamic(light: 0xEB6834, dark: 0xD95926)

    private static func dynamic(light: Int, dark: Int) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let hex = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
            return NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                           blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
        })
    }
}

/// 最近 2 分鐘的流量。滑鼠移上去會顯示那一秒的數值。
struct TrafficChart: View {
    let samples: [TrafficSample]
    @State private var hovered: TrafficSample?

    private var peak: Double { max(samples.map { max($0.down, $0.up) }.max() ?? 0, 10_000) }

    var body: some View {
        Chart {
            ForEach(samples) { s in
                AreaMark(x: .value("Time", s.date), y: .value("Rate", s.down), series: .value("Series", "down"))
                    .foregroundStyle(TrafficColor.down.opacity(0.12))
                    .interpolationMethod(.monotone)
                LineMark(x: .value("Time", s.date), y: .value("Rate", s.down), series: .value("Series", "down"))
                    .foregroundStyle(TrafficColor.down)
                    .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                    .interpolationMethod(.monotone)
                LineMark(x: .value("Time", s.date), y: .value("Rate", s.up), series: .value("Series", "up"))
                    .foregroundStyle(TrafficColor.up)
                    .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                    .interpolationMethod(.monotone)
            }
            if let h = hovered {
                RuleMark(x: .value("Time", h.date))
                    .foregroundStyle(Color.secondary.opacity(0.5))
                    .lineStyle(StrokeStyle(lineWidth: 1))
                PointMark(x: .value("Time", h.date), y: .value("Rate", h.down))
                    .foregroundStyle(TrafficColor.down)
                    .symbolSize(40)
                PointMark(x: .value("Time", h.date), y: .value("Rate", h.up))
                    .foregroundStyle(TrafficColor.up)
                    .symbolSize(40)
            }
        }
        .chartXScale(domain: xDomain)
        .chartYScale(domain: 0...peak * 1.1)
        .chartXAxis(.hidden)
        .chartYAxis {
            AxisMarks(position: .trailing, values: .automatic(desiredCount: 3)) { value in
                AxisGridLine(stroke: StrokeStyle(lineWidth: 0.5)).foregroundStyle(Color.secondary.opacity(0.25))
                AxisValueLabel {
                    if let v = value.as(Double.self) { Text(Rate.short(v)).font(.system(size: 9)).foregroundStyle(.secondary) }
                }
            }
        }
        .chartLegend(.hidden)
        .chartOverlay { proxy in
            GeometryReader { geo in
                Rectangle().fill(.clear).contentShape(Rectangle())
                    .onContinuousHover { phase in
                        switch phase {
                        case .active(let location):
                            guard let frame = proxy.plotFrame else { return }
                            let x = location.x - geo[frame].origin.x
                            if let date: Date = proxy.value(atX: x) {
                                hovered = samples.min { abs($0.date.timeIntervalSince(date)) < abs($1.date.timeIntervalSince(date)) }
                            }
                        case .ended:
                            hovered = nil
                        }
                    }
            }
        }
        .overlay(alignment: .topLeading) {
            if let h = hovered {
                Text(verbatim: "↓ \(Rate.text(h.down))   ↑ \(Rate.text(h.up))")
                    .font(.system(size: 10).monospacedDigit())
                    .padding(.horizontal, 6)
                    .padding(.vertical, 3)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 5))
                    .padding(4)
            }
        }
        .accessibilityLabel(Text("Traffic in the last 2 minutes"))
    }

    private var xDomain: ClosedRange<Date> {
        let end = samples.last?.date ?? Date()
        return end.addingTimeInterval(-Double(TetherModel.historySeconds))...end
    }
}

enum Rate {
    static func text(_ bytesPerSecond: Double) -> String {
        let f = ByteCountFormatter()
        f.countStyle = .decimal
        f.allowedUnits = [.useKB, .useMB, .useGB]
        return f.string(fromByteCount: Int64(bytesPerSecond)) + "/s"
    }

    static func short(_ bytesPerSecond: Double) -> String {
        let f = ByteCountFormatter()
        f.countStyle = .decimal
        f.allowedUnits = [.useKB, .useMB, .useGB]
        f.isAdaptive = false
        return bytesPerSecond < 1 ? "0" : f.string(fromByteCount: Int64(bytesPerSecond)) + "/s"
    }
}
