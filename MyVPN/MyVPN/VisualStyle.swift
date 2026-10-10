import SwiftUI

struct FamilyVPNBrand: View {
    var size: CGFloat = 54
    var body: some View {
        Image("FamilyVPNBrand")
            .resizable().interpolation(.high).scaledToFit()
            .frame(width: size, height: size)
            .clipShape(RoundedRectangle(cornerRadius: size * 0.22))
            .accessibilityHidden(true)
    }
}

/// Shared vector artwork and adaptive layout; no connection state is inferred by the artwork.
struct VPNArtwork: View {
    var shieldSize: CGFloat = 54
    var accentColor: Color = .mint.opacity(0.75)
    var body: some View {
        ZStack {
            ForEach(0..<3) { index in
                Circle().stroke(accentColor.opacity(0.12), lineWidth: 1)
                    .frame(width: CGFloat(90 + index * 38), height: CGFloat(90 + index * 38))
            }
            FamilyVPNBrand(size: shieldSize)
                .opacity(0.7)
        }
        .frame(width: 170, height: 170)
        .accessibilityHidden(true)
    }
}

/// Decorative topology: illustrative routes, never a map of real endpoints or live traffic.
struct VPNNetworkBackdrop: View {
    var color: Color = .mint
    var emphasis: Double = 1
    var centered = false
    var body: some View {
        Canvas { context, size in
            let diameter = max(size.height * 1.6, size.width * 0.62)
            let globe = CGRect(x: size.width * (centered ? 0.50 : 0.70) - diameter / 2,
                               y: size.height * 0.48 - diameter / 2,
                               width: diameter, height: diameter)
            context.stroke(Path(ellipseIn: globe), with: .color(color.opacity(min(1, 0.15 * emphasis))), lineWidth: 1)
            for fraction in [0.28, 0.56, 0.82] {
                let width = diameter * fraction
                let meridian = CGRect(x: globe.midX - width / 2, y: globe.minY,
                                      width: width, height: diameter)
                context.stroke(Path(ellipseIn: meridian), with: .color(color.opacity(min(1, 0.10 * emphasis))), lineWidth: 1)
                let height = diameter * fraction
                let latitude = CGRect(x: globe.minX, y: globe.midY - height / 2,
                                      width: diameter, height: height)
                context.stroke(Path(ellipseIn: latitude), with: .color(color.opacity(min(1, 0.10 * emphasis))), lineWidth: 1)
            }
            let hub = CGPoint(x: size.width * (centered ? 0.50 : 0.71), y: size.height * 0.55)
            let locations: [CGPoint] = [
                CGPoint(x: size.width * 0.40, y: size.height * 0.16),
                CGPoint(x: size.width * 0.52, y: size.height * 0.86),
                CGPoint(x: size.width * 0.84, y: size.height * 0.12),
                CGPoint(x: size.width * 0.97, y: size.height * 0.75),
                CGPoint(x: size.width * 0.30, y: size.height * 0.65)
            ]
            for (index, point) in locations.enumerated() {
                var route = Path()
                route.move(to: point)
                route.addQuadCurve(to: hub, control: CGPoint(x: (point.x + hub.x) / 2,
                                                            y: min(point.y, hub.y) - size.height * 0.30))
                context.stroke(route, with: .color(color.opacity(min(1, 0.32 * emphasis))), style: StrokeStyle(lineWidth: 1.3, lineCap: .round))
                let radius: CGFloat = index.isMultiple(of: 2) ? 4 : 3
                let node = CGRect(x: point.x - radius, y: point.y - radius, width: radius * 2, height: radius * 2)
                context.fill(Path(ellipseIn: node), with: .color(color.opacity(min(1, 0.65 * emphasis))))
                context.stroke(Path(ellipseIn: node.insetBy(dx: -5, dy: -5)), with: .color(color.opacity(min(1, 0.18 * emphasis))), lineWidth: 1)
            }
            context.fill(Path(ellipseIn: CGRect(x: hub.x - 5, y: hub.y - 5, width: 10, height: 10)), with: .color(color.opacity(min(1, 0.65 * emphasis))))
            context.stroke(Path(ellipseIn: CGRect(x: hub.x - 13, y: hub.y - 13, width: 26, height: 26)), with: .color(color.opacity(min(1, 0.24 * emphasis))), lineWidth: 1)
        }
        .mask(LinearGradient(colors: centered ? [.white, .white, .clear] : [.clear, .white.opacity(0.35), .white], startPoint: centered ? .top : .leading, endPoint: centered ? .bottom : .trailing))
        .clipped()
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

private struct VPNPageStyle: ViewModifier {
    let title: String
    let subtitle: String
    let icon: String
    @Environment(\.colorScheme) private var scheme
    @ScaledMetric private var headingSize = 26
    func body(content: Content) -> some View {
        content
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            .tint(Color(red: 0.05, green: 0.49, blue: 0.51))
            .background {
                ZStack {
                    (scheme == .dark ? Color(red: 0.07, green: 0.11, blue: 0.16) : Color(red: 0.94, green: 0.96, blue: 0.97))
                    LinearGradient(colors: [.teal.opacity(0.08), .clear, .blue.opacity(0.05)], startPoint: .topLeading, endPoint: .bottomTrailing)
                    VStack {
                        VPNNetworkBackdrop().frame(height: 420).opacity(scheme == .dark ? 0.32 : 0.24)
                        Spacer(minLength: 0)
                    }
                }.ignoresSafeArea()
            }
            .safeAreaInset(edge: .top, spacing: 0) {
                HStack(spacing: 20) {
                    VStack(alignment: .leading, spacing: 10) {
                        Label("FAMILY VPN", systemImage: icon)
                            .font(.caption.weight(.semibold)).tracking(2).foregroundStyle(.mint)
                        Text(title).font(.system(size: headingSize, weight: .bold, design: .rounded))
                            .foregroundStyle(.white)
                        Text(subtitle).font(.subheadline).foregroundStyle(.white.opacity(0.8))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 0)
                    FamilyVPNBrand(size: 58)
                }
                .padding(.horizontal, 28).padding(.vertical, 24)
                .background {
                    ZStack {
                        LinearGradient(colors: [Color(red: 0.07, green: 0.17, blue: 0.26), Color(red: 0.08, green: 0.30, blue: 0.35)], startPoint: .topLeading, endPoint: .bottomTrailing)
                        VPNNetworkBackdrop()
                        GeometryReader { geometry in
                            Circle().fill(.mint.opacity(0.06)).frame(width: 340, height: 340)
                                .offset(x: geometry.size.width - 220, y: -170)
                        }.clipped()
                    }
                }
            }
            #if os(macOS)
            .font(.system(size: 15))
            .frame(minWidth: 400, idealWidth: 460, maxWidth: 540, minHeight: 720, idealHeight: 860)
            #endif
    }
}

extension View {
    func vpnPage(title: String, subtitle: String, icon: String) -> some View {
        modifier(VPNPageStyle(title: title, subtitle: subtitle, icon: icon))
    }
}
