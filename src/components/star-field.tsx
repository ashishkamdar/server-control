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

export function StarField({ className, style }: { className?: string; style?: React.CSSProperties }) {
  const starsRef = useRef<StarData[]>([])
  if (starsRef.current.length === 0) {
    starsRef.current = generateStars(80)
  }
  const stars = starsRef.current

  return (
    <div className={`absolute inset-0 ${className || ''}`} style={style}>
      {/* Constellation connecting lines */}
      <ConstellationLines />

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
      `}</style>
    </div>
  )
}
