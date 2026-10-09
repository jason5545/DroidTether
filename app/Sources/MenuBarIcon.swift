import AppKit

/// 選單列圖示：照 assets/menubar-*.svg 的幾何用向量畫，當 template image，深淺色模式自動換色。
/// 跟原版一樣，開著和關著要一眼分得出來：開著是實心手機（箭頭鏤空），關著是空心手機。
enum MenuBarIcon {
    enum Style {
        case on          // 已連線
        case connecting  // 連線中
        case off         // 沒接手機、沒開分享
        case inactive    // 暫停、背景服務沒跑
    }

    static func image(_ style: Style) -> NSImage {
        let img = NSImage(size: NSSize(width: 18, height: 18), flipped: true) { _ in
            let alpha: CGFloat = switch style {
            case .on, .off: 1
            case .connecting: 0.55
            case .inactive: 0.4
            }
            NSColor.black.withAlphaComponent(alpha).set()

            let bodyRect = NSRect(x: 4.7, y: 0.9, width: 8.6, height: 12.2)
            if style == .on {
                NSBezierPath(roundedRect: bodyRect.insetBy(dx: -0.7, dy: -0.7), xRadius: 2.6, yRadius: 2.6).fill()
            } else {
                let body = NSBezierPath(roundedRect: bodyRect, xRadius: 2, yRadius: 2)
                body.lineWidth = 1.4
                body.stroke()
            }

            let cable = NSBezierPath()
            cable.move(to: NSPoint(x: 9, y: 14.6))
            cable.line(to: NSPoint(x: 9, y: 17.3))
            cable.lineWidth = 1.4
            cable.lineCapStyle = .round
            cable.stroke()
            NSBezierPath(roundedRect: NSRect(x: 7.5, y: 13, width: 3, height: 2), xRadius: 0.6, yRadius: 0.6).fill()

            if style == .on || style == .connecting {
                let a = arrows()
                if style == .on {
                    // 實心時把箭頭挖空
                    NSGraphicsContext.current?.compositingOperation = .clear
                    a.stroke()
                    NSGraphicsContext.current?.compositingOperation = .sourceOver
                } else {
                    a.stroke()
                }
            }
            return true
        }
        img.isTemplate = true
        return img
    }

    private static func arrows() -> NSBezierPath {
        let a = NSBezierPath()
        a.move(to: NSPoint(x: 7.4, y: 10.2))
        a.line(to: NSPoint(x: 7.4, y: 3.8))
        a.move(to: NSPoint(x: 5.9, y: 5.3))
        a.line(to: NSPoint(x: 7.4, y: 3.8))
        a.line(to: NSPoint(x: 8.9, y: 5.3))
        a.move(to: NSPoint(x: 10.6, y: 3.8))
        a.line(to: NSPoint(x: 10.6, y: 10.2))
        a.move(to: NSPoint(x: 9.1, y: 8.7))
        a.line(to: NSPoint(x: 10.6, y: 10.2))
        a.line(to: NSPoint(x: 12.1, y: 8.7))
        a.lineWidth = 1.2
        a.lineCapStyle = .round
        a.lineJoinStyle = .round
        return a
    }
}
