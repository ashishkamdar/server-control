'use client'

import { useEffect, useRef, useState } from 'react'

interface StarData {
  x: number
  y: number
  size: number
  opacity: number
  duration: number
  delay: number
}

interface ShootingStar {
  id: number
  startX: number
  startY: number
  angle: number
  length: number
  duration: number
}

function generateStars(count: number): StarData[] {
  const stars: StarData[] = []
  for (let i = 0; i < count; i++) {
    stars.push({
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: Math.random() < 0.15 ? Math.random() * 1.5 + 1.5 : Math.random() * 1 + 0.5,
      opacity: Math.random() < 0.15 ? Math.random() * 0.3 + 0.7 : Math.random() * 0.5 + 0.2,
      duration: Math.random() * 3 + 2,
      delay: Math.random() * 4,
    })
  }
  return stars
}

// Constellation lines
const CONSTELLATION_LINES = [
  [[72, 18], [78, 25], [85, 15], [72, 18]],
  [[30, 40], [38, 35], [45, 42], [52, 38]],
  [[15, 70], [22, 65], [28, 72], [15, 70]],
  [[60, 55], [68, 50], [75, 58], [70, 62], [60, 55]],
]

function ConstellationLines() {
  const containerRef = useRef<HTMLDivElement>(null)
  const svgRef = useRef<SVGSVGElement>(null)

  useEffect(() => {
    const svg = svgRef.current
    const container = containerRef.current
    if (!svg || !container) return

    const w = container.offsetWidth
    const h = container.offsetHeight

    // Set viewBox to match actual pixel dimensions
    svg.setAttribute('viewBox', `0 0 ${w} ${h}`)

    const paths = svg.querySelectorAll('path')
    const animations: Animation[] = []

    paths.forEach((path) => {
      // Convert percentage-based points to actual pixels
      const points = path.dataset.points
      if (!points) return
      const parsed = JSON.parse(points) as number[][]
      const d = parsed.map((p, j) => `${j === 0 ? 'M' : 'L'} ${(p[0] / 100) * w} ${(p[1] / 100) * h}`).join(' ')
      path.setAttribute('d', d)

      const length = path.getTotalLength()
      path.style.strokeDasharray = `${length}`
      path.style.strokeDashoffset = `${length}`

      const anim = path.animate(
        [
          { strokeDashoffset: `${length}`, opacity: '0' },
          { strokeDashoffset: '0', opacity: '0.3' },
        ],
        {
          duration: 4000 + Math.random() * 3000,
          delay: 2000 + Math.random() * 3000,
          fill: 'forwards' as FillMode,
          easing: 'ease-out',
        }
      )
      animations.push(anim)
    })

    return () => animations.forEach(a => a.cancel())
  }, [])

  return (
    <div ref={containerRef} className="pointer-events-none absolute inset-0">
      <svg ref={svgRef} className="absolute inset-0 h-full w-full">
        {CONSTELLATION_LINES.map((points, i) => (
          <path
            key={i}
            data-points={JSON.stringify(points)}
            d=""
            fill="none"
            stroke="rgba(125, 211, 252, 0.3)"
            strokeWidth="1"
            opacity="0"
          />
        ))}
      </svg>
    </div>
  )
}

function ShootingStars() {
  const [shootingStars, setShootingStars] = useState<ShootingStar[]>([])
  const counterRef = useRef(0)

  useEffect(() => {
    const spawn = () => {
      counterRef.current++
      const star: ShootingStar = {
        id: counterRef.current,
        startX: Math.random() * 70 + 10,
        startY: Math.random() * 40,
        angle: 25 + Math.random() * 30,  // 25-55 degrees downward
        length: 80 + Math.random() * 120,
        duration: 0.6 + Math.random() * 0.8,
      }
      setShootingStars(prev => [...prev, star])

      // Remove after animation ends
      setTimeout(() => {
        setShootingStars(prev => prev.filter(s => s.id !== star.id))
      }, star.duration * 1000 + 500)
    }

    // First shooting star after 2-4s, then every 3-8s
    const firstTimeout = setTimeout(spawn, 2000 + Math.random() * 2000)
    const interval = setInterval(() => {
      spawn()
    }, 3000 + Math.random() * 5000)

    return () => {
      clearTimeout(firstTimeout)
      clearInterval(interval)
    }
  }, [])

  return (
    <>
      {shootingStars.map(star => {
        const rad = (star.angle * Math.PI) / 180
        const endX = star.startX + Math.cos(rad) * (star.length / 10)
        const endY = star.startY + Math.sin(rad) * (star.length / 10)

        return (
          <div
            key={star.id}
            className="absolute"
            style={{
              left: `${star.startX}%`,
              top: `${star.startY}%`,
              width: `${star.length}px`,
              height: '2px',
              transform: `rotate(${star.angle}deg)`,
              transformOrigin: 'left center',
              animation: `shootingStar ${star.duration}s ease-out forwards`,
            }}
          >
            {/* Bright head */}
            <div
              className="absolute right-0 top-1/2 -translate-y-1/2 rounded-full bg-white shadow-[0_0_6px_2px_rgba(125,211,252,0.6)]"
              style={{ width: '3px', height: '3px' }}
            />
            {/* Glowing tail */}
            <div
              className="absolute inset-0 rounded-full"
              style={{
                background: 'linear-gradient(to right, transparent 0%, rgba(125, 211, 252, 0.1) 30%, rgba(125, 211, 252, 0.4) 70%, rgba(255, 255, 255, 0.8) 100%)',
                borderRadius: '1px',
              }}
            />
          </div>
        )
      })}
    </>
  )
}

function Sun() {
  return (
    <div
      className="absolute"
      style={{
        left: '-30px',
        top: '5%',
        width: '120px',
        height: '120px',
        animation: 'planetDrift 50s ease-in-out infinite alternate',
      }}
    >
      {/* Corona / outer glow */}
      <div
        className="absolute -inset-8 rounded-full"
        style={{
          background: 'radial-gradient(circle, rgba(255, 200, 50, 0.08) 20%, rgba(255, 160, 20, 0.04) 45%, transparent 70%)',
          animation: 'sunPulse 4s ease-in-out infinite alternate',
        }}
      />
      {/* Mid glow */}
      <div
        className="absolute -inset-4 rounded-full"
        style={{
          background: 'radial-gradient(circle, rgba(255, 210, 80, 0.12) 30%, rgba(255, 180, 40, 0.06) 60%, transparent 75%)',
        }}
      />
      {/* Sun body */}
      <svg viewBox="0 0 200 200" className="absolute inset-0 h-full w-full">
        <defs>
          <radialGradient id="sun-body" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#fff8e0" />
            <stop offset="25%" stopColor="#ffe870" />
            <stop offset="50%" stopColor="#ffcc30" />
            <stop offset="75%" stopColor="#ff9d00" />
            <stop offset="100%" stopColor="#e07000" />
          </radialGradient>
          <radialGradient id="sun-inner" cx="45%" cy="42%" r="30%">
            <stop offset="0%" stopColor="rgba(255,255,255,0.5)" />
            <stop offset="100%" stopColor="transparent" />
          </radialGradient>
          <filter id="sun-blur">
            <feGaussianBlur stdDeviation="1.5" />
          </filter>
        </defs>
        <circle cx="100" cy="100" r="96" fill="url(#sun-body)" />
        {/* Surface granulation */}
        <g opacity="0.15" filter="url(#sun-blur)">
          <circle cx="80" cy="75" r="12" fill="#ffaa20" />
          <circle cx="115" cy="90" r="15" fill="#ff9510" />
          <circle cx="90" cy="110" r="10" fill="#ffbb30" />
          <circle cx="120" cy="70" r="8" fill="#ff8800" />
          <circle cx="70" cy="100" r="11" fill="#ffaa20" />
          <circle cx="105" cy="120" r="9" fill="#ff9510" />
          <circle cx="130" cy="105" r="7" fill="#ffbb30" />
        </g>
        {/* Sunspot */}
        <circle cx="88" cy="95" r="5" fill="rgba(180, 80, 0, 0.3)" filter="url(#sun-blur)" />
        <circle cx="118" cy="85" r="3" fill="rgba(180, 80, 0, 0.2)" filter="url(#sun-blur)" />
        {/* Bright center */}
        <circle cx="100" cy="100" r="96" fill="url(#sun-inner)" />
      </svg>
    </div>
  )
}

function EarthMoon() {
  return (
    <div
      className="absolute"
      style={{
        right: '12%',
        bottom: '15%',
        animation: 'planetDrift 40s ease-in-out infinite alternate',
      }}
    >
      {/* Earth */}
      <div className="relative" style={{ width: '90px', height: '90px' }}>
        <svg viewBox="0 0 200 200" className="absolute inset-0 h-full w-full" style={{ filter: 'drop-shadow(0 0 12px rgba(80, 160, 255, 0.2))' }}>
          <defs>
            {/* Ocean gradient */}
            <radialGradient id="earth-ocean" cx="40%" cy="35%" r="50%">
              <stop offset="0%" stopColor="#4a9eff" />
              <stop offset="50%" stopColor="#1a6dd4" />
              <stop offset="100%" stopColor="#0a3a7a" />
            </radialGradient>
            {/* Shadow overlay */}
            <radialGradient id="earth-shadow" cx="75%" cy="65%" r="55%">
              <stop offset="0%" stopColor="transparent" />
              <stop offset="60%" stopColor="rgba(0,0,0,0.15)" />
              <stop offset="100%" stopColor="rgba(0,0,0,0.65)" />
            </radialGradient>
            {/* Atmosphere */}
            <radialGradient id="earth-atmo" cx="50%" cy="50%" r="50%">
              <stop offset="85%" stopColor="transparent" />
              <stop offset="95%" stopColor="rgba(100, 180, 255, 0.15)" />
              <stop offset="100%" stopColor="rgba(100, 180, 255, 0.05)" />
            </radialGradient>
            {/* Specular highlight */}
            <radialGradient id="earth-spec" cx="35%" cy="30%" r="25%">
              <stop offset="0%" stopColor="rgba(255,255,255,0.25)" />
              <stop offset="100%" stopColor="transparent" />
            </radialGradient>
            <clipPath id="earth-clip"><circle cx="100" cy="100" r="97" /></clipPath>
          </defs>

          {/* Ocean base */}
          <circle cx="100" cy="100" r="97" fill="url(#earth-ocean)" />

          {/* Continents */}
          <g clipPath="url(#earth-clip)" fill="#3a8a4a" opacity="0.85">
            {/* North America */}
            <path d="M55 38 Q60 32 68 30 Q72 28 76 32 Q80 38 78 45 Q82 48 80 55 Q76 60 70 62 Q65 65 58 60 Q52 55 50 48 Q48 42 55 38Z" />
            {/* South America */}
            <path d="M72 78 Q76 72 80 74 Q84 78 82 85 Q80 95 76 102 Q72 108 68 112 Q65 116 66 108 Q64 100 66 92 Q68 85 72 78Z" />
            {/* Europe */}
            <path d="M98 34 Q104 30 110 32 Q114 34 112 38 Q108 42 104 40 Q100 38 98 34Z" />
            {/* Africa */}
            <path d="M102 52 Q108 48 114 50 Q120 54 122 62 Q124 72 120 82 Q116 90 110 95 Q106 98 104 92 Q100 84 98 74 Q96 64 100 56 Q101 53 102 52Z" />
            {/* Asia */}
            <path d="M116 28 Q124 24 134 26 Q142 28 148 34 Q152 40 150 48 Q146 55 138 58 Q130 60 124 56 Q118 50 116 42 Q114 34 116 28Z" />
            {/* Australia hint */}
            <path d="M148 82 Q154 78 160 80 Q164 84 162 90 Q158 94 152 92 Q148 88 148 82Z" />
          </g>

          {/* Land detail — lighter patches */}
          <g clipPath="url(#earth-clip)" fill="#5aaa5a" opacity="0.4">
            <path d="M60 40 Q65 36 70 38 Q72 42 68 46 Q64 44 60 40Z" />
            <path d="M130 32 Q136 30 140 34 Q138 38 132 36 Q130 34 130 32Z" />
            <path d="M108 56 Q112 54 116 58 Q114 64 108 62 Q106 58 108 56Z" />
          </g>

          {/* Desert regions */}
          <g clipPath="url(#earth-clip)" fill="#c4a55a" opacity="0.35">
            <path d="M104 50 Q110 48 114 52 Q112 56 106 54 Q104 52 104 50Z" />
            <path d="M126 36 Q132 34 136 38 Q134 42 128 40 Q126 38 126 36Z" />
          </g>

          {/* Clouds */}
          <g clipPath="url(#earth-clip)" fill="white" opacity="0.3">
            <ellipse cx="70" cy="50" rx="18" ry="5" transform="rotate(-10 70 50)" />
            <ellipse cx="120" cy="40" rx="14" ry="4" transform="rotate(5 120 40)" />
            <ellipse cx="90" cy="72" rx="22" ry="5" transform="rotate(-5 90 72)" />
            <ellipse cx="140" cy="65" rx="12" ry="3" transform="rotate(8 140 65)" />
            <ellipse cx="60" cy="88" rx="16" ry="4" transform="rotate(-8 60 88)" />
            <ellipse cx="110" cy="85" rx="20" ry="4" transform="rotate(3 110 85)" />
          </g>

          {/* Shadow */}
          <circle cx="100" cy="100" r="97" fill="url(#earth-shadow)" />
          {/* Specular highlight */}
          <circle cx="100" cy="100" r="97" fill="url(#earth-spec)" />
          {/* Atmosphere rim */}
          <circle cx="100" cy="100" r="99" fill="none" stroke="rgba(100, 180, 255, 0.2)" strokeWidth="3" />
          <circle cx="100" cy="100" r="97" fill="url(#earth-atmo)" />
        </svg>
      </div>

      {/* Moon — orbiting Earth */}
      <div
        className="absolute"
        style={{
          right: '-35px',
          top: '-25px',
          width: '32px',
          height: '32px',
          animation: 'moonOrbit 60s linear infinite',
        }}
      >
        <svg viewBox="0 0 100 100" className="h-full w-full" style={{ filter: 'drop-shadow(0 0 4px rgba(200, 200, 210, 0.15))' }}>
          <defs>
            <radialGradient id="moon-base" cx="40%" cy="35%" r="50%">
              <stop offset="0%" stopColor="#e8e4dc" />
              <stop offset="50%" stopColor="#c8c0b4" />
              <stop offset="100%" stopColor="#8a8078" />
            </radialGradient>
            <radialGradient id="moon-shadow" cx="72%" cy="62%" r="50%">
              <stop offset="0%" stopColor="transparent" />
              <stop offset="50%" stopColor="rgba(0,0,0,0.1)" />
              <stop offset="100%" stopColor="rgba(0,0,0,0.55)" />
            </radialGradient>
            <radialGradient id="moon-spec" cx="32%" cy="28%" r="20%">
              <stop offset="0%" stopColor="rgba(255,255,255,0.3)" />
              <stop offset="100%" stopColor="transparent" />
            </radialGradient>
          </defs>

          {/* Base */}
          <circle cx="50" cy="50" r="48" fill="url(#moon-base)" />

          {/* Craters */}
          <g opacity="0.4">
            <circle cx="35" cy="38" r="8" fill="none" stroke="#9a9088" strokeWidth="1" />
            <ellipse cx="35" cy="38" rx="7" ry="7" fill="rgba(0,0,0,0.06)" />

            <circle cx="58" cy="30" r="5" fill="none" stroke="#9a9088" strokeWidth="0.8" />
            <ellipse cx="58" cy="30" rx="4.5" ry="4.5" fill="rgba(0,0,0,0.05)" />

            <circle cx="45" cy="60" r="10" fill="none" stroke="#9a9088" strokeWidth="1" />
            <ellipse cx="45" cy="60" rx="9" ry="9" fill="rgba(0,0,0,0.07)" />

            <circle cx="65" cy="52" r="6" fill="none" stroke="#9a9088" strokeWidth="0.8" />
            <ellipse cx="65" cy="52" rx="5.5" ry="5.5" fill="rgba(0,0,0,0.05)" />

            <circle cx="28" cy="55" r="4" fill="none" stroke="#9a9088" strokeWidth="0.6" />
            <circle cx="55" cy="72" r="3" fill="none" stroke="#9a9088" strokeWidth="0.5" />
            <circle cx="38" cy="25" r="3" fill="none" stroke="#9a9088" strokeWidth="0.5" />
            <circle cx="70" cy="38" r="3.5" fill="none" stroke="#9a9088" strokeWidth="0.6" />
          </g>

          {/* Mare (dark patches) */}
          <g opacity="0.12">
            <ellipse cx="38" cy="42" rx="12" ry="10" fill="#5a5048" />
            <ellipse cx="55" cy="58" rx="14" ry="11" fill="#5a5048" transform="rotate(15 55 58)" />
            <ellipse cx="32" cy="60" rx="8" ry="6" fill="#5a5048" />
          </g>

          {/* Shadow + highlight */}
          <circle cx="50" cy="50" r="48" fill="url(#moon-shadow)" />
          <circle cx="50" cy="50" r="48" fill="url(#moon-spec)" />
        </svg>
      </div>
    </div>
  )
}

function Planets() {
  return (
    <>
      {/* Saturn — top right, large with ring */}
      <div
        className="absolute"
        style={{
          right: '8%',
          top: '12%',
          width: '80px',
          height: '80px',
          animation: 'planetDrift 30s ease-in-out infinite alternate',
        }}
      >
        {/* Planet body */}
        <div
          className="absolute inset-0 rounded-full"
          style={{
            background: 'radial-gradient(circle at 35% 35%, #e8d5a3 0%, #c4956a 40%, #8b6040 70%, #4a3020 100%)',
            boxShadow: '0 0 20px 4px rgba(200, 160, 100, 0.15), inset -8px -4px 16px rgba(0,0,0,0.5)',
          }}
        />
        {/* Band detail */}
        <div
          className="absolute rounded-full"
          style={{
            left: '10%', right: '10%', top: '38%', height: '8%',
            background: 'rgba(180, 140, 80, 0.3)',
            filter: 'blur(1px)',
          }}
        />
        <div
          className="absolute rounded-full"
          style={{
            left: '8%', right: '8%', top: '52%', height: '6%',
            background: 'rgba(160, 120, 70, 0.25)',
            filter: 'blur(1px)',
          }}
        />
        {/* Ring */}
        <div
          className="absolute"
          style={{
            left: '-45%',
            right: '-45%',
            top: '30%',
            height: '40%',
            borderRadius: '50%',
            border: '3px solid rgba(210, 180, 130, 0.3)',
            boxShadow: '0 0 10px 2px rgba(200, 170, 120, 0.12)',
            transform: 'rotateX(55deg) rotateZ(-15deg)',
          }}
        />
        {/* Middle ring */}
        <div
          className="absolute"
          style={{
            left: '-55%',
            right: '-55%',
            top: '28%',
            height: '44%',
            borderRadius: '50%',
            border: '2px solid rgba(200, 170, 120, 0.2)',
            transform: 'rotateX(55deg) rotateZ(-15deg)',
          }}
        />
        {/* Outer ring */}
        <div
          className="absolute"
          style={{
            left: '-65%',
            right: '-65%',
            top: '26%',
            height: '48%',
            borderRadius: '50%',
            border: '1px solid rgba(200, 170, 120, 0.1)',
            transform: 'rotateX(55deg) rotateZ(-15deg)',
          }}
        />
        {/* Atmosphere glow */}
        <div
          className="absolute -inset-2 rounded-full"
          style={{
            background: 'radial-gradient(circle, rgba(200, 160, 100, 0.08) 40%, transparent 70%)',
          }}
        />
      </div>

      {/* Blue-purple gas giant — bottom left, medium */}
      <div
        className="absolute"
        style={{
          left: '5%',
          bottom: '18%',
          width: '55px',
          height: '55px',
          animation: 'planetDrift 25s 5s ease-in-out infinite alternate-reverse',
        }}
      >
        <div
          className="absolute inset-0 rounded-full"
          style={{
            background: 'radial-gradient(circle at 30% 30%, #7ba4d4 0%, #4a6fa5 35%, #2d4a7a 60%, #1a2d50 100%)',
            boxShadow: '0 0 15px 3px rgba(100, 150, 220, 0.12), inset -6px -3px 12px rgba(0,0,0,0.5)',
          }}
        />
        {/* Storm bands */}
        <div className="absolute rounded-full" style={{ left: '12%', right: '12%', top: '30%', height: '5%', background: 'rgba(140, 180, 230, 0.2)', filter: 'blur(1px)' }} />
        <div className="absolute rounded-full" style={{ left: '10%', right: '10%', top: '55%', height: '7%', background: 'rgba(100, 150, 200, 0.15)', filter: 'blur(1.5px)' }} />
        <div className="absolute rounded-full" style={{ left: '15%', right: '15%', top: '70%', height: '4%', background: 'rgba(120, 160, 210, 0.2)', filter: 'blur(1px)' }} />
        {/* Atmosphere */}
        <div className="absolute -inset-1.5 rounded-full" style={{ background: 'radial-gradient(circle, rgba(100, 150, 220, 0.06) 40%, transparent 70%)' }} />
      </div>

      {/* Small red-orange Mars — center-left area */}
      <div
        className="absolute"
        style={{
          left: '25%',
          top: '60%',
          width: '22px',
          height: '22px',
          animation: 'planetDrift 20s 10s ease-in-out infinite alternate',
        }}
      >
        <div
          className="absolute inset-0 rounded-full"
          style={{
            background: 'radial-gradient(circle at 35% 35%, #d4886a 0%, #b5654a 40%, #8a4030 70%, #5a2518 100%)',
            boxShadow: '0 0 8px 2px rgba(180, 100, 60, 0.1), inset -3px -2px 6px rgba(0,0,0,0.5)',
          }}
        />
      </div>

      {/* Tiny distant planet — upper center */}
      <div
        className="absolute"
        style={{
          left: '45%',
          top: '8%',
          width: '12px',
          height: '12px',
          animation: 'planetDrift 35s 8s ease-in-out infinite alternate-reverse',
        }}
      >
        <div
          className="absolute inset-0 rounded-full"
          style={{
            background: 'radial-gradient(circle at 30% 30%, #a8c8e8 0%, #6a8ab0 50%, #3a5a80 100%)',
            boxShadow: '0 0 6px 1px rgba(120, 170, 220, 0.1), inset -2px -1px 4px rgba(0,0,0,0.4)',
          }}
        />
      </div>
    </>
  )
}

export function StarField({ className, style }: { className?: string; style?: React.CSSProperties }) {
  const starsRef = useRef<StarData[]>([])
  if (starsRef.current.length === 0) {
    starsRef.current = generateStars(200)
  }
  const stars = starsRef.current

  return (
    <div className={`absolute inset-0 ${className || ''}`} style={style}>
      {/* Constellation connecting lines */}
      <ConstellationLines />

      {/* Sun */}
      <Sun />

      {/* Earth & Moon */}
      <EarthMoon />

      {/* Planets */}
      <Planets />

      {/* Shooting stars */}
      <ShootingStars />

      {/* Individual twinkling stars */}
      {stars.map((star, i) => (
        <div
          key={i}
          className="absolute rounded-full bg-white"
          style={{
            left: `${star.x}%`,
            top: `${star.y}%`,
            width: `${star.size}px`,
            height: `${star.size}px`,
            opacity: star.opacity,
            animation: `twinkle ${star.duration}s ${star.delay}s ease-in-out infinite alternate`,
          }}
        />
      ))}

      <style jsx>{`
        @keyframes twinkle {
          0% { opacity: 0.15; transform: scale(0.8); }
          100% { opacity: 0.7; transform: scale(1.2); }
        }
        @keyframes shootingStar {
          0% { opacity: 0; width: 0; }
          10% { opacity: 1; }
          70% { opacity: 1; }
          100% { opacity: 0; }
        }
        @keyframes planetDrift {
          0% { transform: translate(0, 0); }
          100% { transform: translate(8px, 5px); }
        }
        @keyframes moonOrbit {
          0% { transform: rotate(0deg) translateX(12px) rotate(0deg); }
          100% { transform: rotate(360deg) translateX(12px) rotate(-360deg); }
        }
        @keyframes sunPulse {
          0% { transform: scale(1); opacity: 0.8; }
          100% { transform: scale(1.08); opacity: 1; }
        }
      `}</style>
    </div>
  )
}
