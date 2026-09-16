import React, { useEffect, useState, useMemo, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../../context/AppContext';
import {
  fetchProjectRiskMap,
  type RiskMapGraphResponseData,
  type RiskMapNodeData,
  type RiskMapEdgeData,
} from '../../api/risk_map';

interface PositionedNode extends RiskMapNodeData {
  posX: number;
  posY: number;
}

export const RiskMap: React.FC = () => {
  const navigate = useNavigate();
  const { activeProjectId } = useApp();

  const [graphData, setGraphData] = useState<RiskMapGraphResponseData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [zoomScale, setZoomScale] = useState<number>(0.85);
  const [panOffset, setPanOffset] = useState<{ x: number; y: number }>({ x: 40, y: 40 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isExplorerExpanded, setIsExplorerExpanded] = useState<boolean>(true);
  const [severityFilter, setSeverityFilter] = useState<string>('');

  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (activeProjectId && !isNaN(Number(activeProjectId))) {
      setLoading(true);
      fetchProjectRiskMap(Number(activeProjectId), {
        severity: severityFilter || undefined,
      })
        .then((data) => {
          setGraphData(data);
          if (data.nodes.length > 0 && !selectedNodeId) {
            setSelectedNodeId(data.nodes[0].id);
          }
        })
        .catch(() => setGraphData(null))
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, [activeProjectId, severityFilter]);

  // Dynamic Topology Layout Calculation
  const positionedNodes = useMemo<PositionedNode[]>(() => {
    if (!graphData || !graphData.nodes.length) return [];

    const nodes = graphData.nodes;
    const layerMap: Record<string, RiskMapNodeData[]> = {
      PROJECT: [],
      API: [],
      ENDPOINT: [],
      FINDING: [],
      VULNERABILITY: [],
      FILE: [],
    };

    nodes.forEach((node) => {
      const type = node.type.toUpperCase();
      if (layerMap[type]) {
        layerMap[type].push(node);
      } else {
        layerMap['FINDING'].push(node);
      }
    });

    const layerXCoords: Record<string, number> = {
      PROJECT: 80,
      API: 360,
      ENDPOINT: 680,
      FINDING: 1020,
      VULNERABILITY: 1380,
      FILE: 1380,
    };

    const result: PositionedNode[] = [];

    // Layout each layer dynamically
    Object.keys(layerMap).forEach((layerKey) => {
      const layerNodes = layerMap[layerKey];
      const x = layerXCoords[layerKey] || 1000;
      const count = layerNodes.length;

      if (count === 0) return;

      const spacingY = Math.max(75, Math.min(110, 800 / Math.max(count, 1)));
      const startY = 100;

      layerNodes.forEach((node, idx) => {
        let posY = startY + idx * spacingY;
        if (node.type === 'FILE') {
          posY += 45; // Stagger source file nodes relative to CWE vulnerability nodes
        }

        result.push({
          ...node,
          posX: x,
          posY: posY,
        });
      });
    });

    return result;
  }, [graphData]);

  const edges: RiskMapEdgeData[] = graphData?.edges || [];
  const selectedNode = selectedNodeId ? positionedNodes.find((n) => n.id === selectedNodeId) : null;

  // Fit to View algorithm
  const handleFitToView = () => {
    if (!positionedNodes.length) return;

    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    positionedNodes.forEach((n) => {
      minX = Math.min(minX, n.posX);
      maxX = Math.max(maxX, n.posX + 220);
      minY = Math.min(minY, n.posY);
      maxY = Math.max(maxY, n.posY + 80);
    });

    const graphWidth = maxX - minX || 800;
    const graphHeight = maxY - minY || 600;

    const containerWidth = containerRef.current?.clientWidth || 1000;
    const containerHeight = containerRef.current?.clientHeight || 700;

    const scaleX = (containerWidth - 120) / graphWidth;
    const scaleY = (containerHeight - 120) / graphHeight;
    const optimalScale = Math.min(1.2, Math.max(0.35, Math.min(scaleX, scaleY)));

    setZoomScale(optimalScale);
    setPanOffset({
      x: Math.max(20, (containerWidth - graphWidth * optimalScale) / 2 - minX * optimalScale),
      y: Math.max(20, (containerHeight - graphHeight * optimalScale) / 2 - minY * optimalScale),
    });
  };

  const handleZoomIn = () => setZoomScale((prev) => Math.min(2.0, prev + 0.15));
  const handleZoomOut = () => setZoomScale((prev) => Math.max(0.25, prev - 0.15));

  // Canvas Mouse Drag Panning Handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return; // Only main click
    setIsDragging(true);
    setDragStart({ x: e.clientX - panOffset.x, y: e.clientY - panOffset.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPanOffset({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  };

  const handleMouseUp = () => setIsDragging(false);

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const zoomDelta = e.deltaY < 0 ? 0.08 : -0.08;
    setZoomScale((prev) => Math.min(2.0, Math.max(0.25, prev + zoomDelta)));
  };

  return (
    <div className="flex-1 flex h-[calc(100vh-64px)] overflow-hidden text-on-surface select-none">
      {/* Left Panel: File / Asset Explorer */}
      {isExplorerExpanded ? (
        <aside className="w-80 flex-shrink-0 border-r border-outline-variant/30 bg-surface-container-lowest flex flex-col h-full transition-all duration-300">
          <div className="p-4 border-b border-outline-variant/30 flex items-center justify-between">
            <h2 className="font-label-mono text-label-mono text-on-surface-variant uppercase tracking-wider">
              Asset Explorer ({positionedNodes.length})
            </h2>
            <button
              onClick={() => setIsExplorerExpanded(false)}
              className="text-on-surface-variant hover:text-on-surface cursor-pointer bg-transparent border-none"
              title="Collapse Panel"
            >
              <span className="material-symbols-outlined text-[18px]">menu_open</span>
            </button>
          </div>

          <div className="p-4 border-b border-outline-variant/20 flex flex-col gap-2 shrink-0">
            <div className="flex gap-2 overflow-x-auto pb-1 font-label-mono">
              <button
                onClick={() => setSeverityFilter('')}
                className={`px-3 py-1 rounded-full text-[10px] whitespace-nowrap cursor-pointer border ${
                  !severityFilter ? 'bg-primary/20 border-primary text-primary font-bold' : 'bg-[#1c2026] border-[#1F242D] text-on-surface-variant'
                }`}
              >
                All Severity
              </button>
              <button
                onClick={() => setSeverityFilter('critical')}
                className={`px-3 py-1 rounded-full text-[10px] whitespace-nowrap cursor-pointer border ${
                  severityFilter === 'critical' ? 'bg-error/20 border-error text-error font-bold' : 'bg-[#1c2026] border-[#1F242D] text-on-surface-variant'
                }`}
              >
                Critical
              </button>
              <button
                onClick={() => setSeverityFilter('high')}
                className={`px-3 py-1 rounded-full text-[10px] whitespace-nowrap cursor-pointer border ${
                  severityFilter === 'high' ? 'bg-[#ff9800]/20 border-[#ff9800] text-[#ff9800] font-bold' : 'bg-[#1c2026] border-[#1F242D] text-on-surface-variant'
                }`}
              >
                High
              </button>
            </div>
          </div>

          {/* Tree View list */}
          <div className="flex-1 overflow-y-auto p-2 space-y-1 text-sm font-label-mono">
            {positionedNodes.map((node) => {
              const isSelected = selectedNodeId === node.id;
              const isCrit = node.status === 'critical';
              const isWarn = node.status === 'warning';
              return (
                <div
                  key={node.id}
                  onClick={() => setSelectedNodeId(node.id)}
                  className={`flex items-center justify-between p-2 rounded cursor-pointer border transition-colors ${
                    isSelected
                      ? 'bg-primary/20 border-primary text-primary font-bold'
                      : isCrit
                      ? 'bg-error/10 border-error/20 text-error/90 hover:bg-error/15'
                      : isWarn
                      ? 'bg-[#ff9800]/10 border-[#ff9800]/20 text-[#ff9800] hover:bg-[#ff9800]/15'
                      : 'hover:bg-surface-container-high text-on-surface border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-2 truncate">
                    <span className="material-symbols-outlined text-sm">{node.icon}</span>
                    <span className="text-xs truncate">{node.label}</span>
                  </div>
                  <span className="text-[9px] uppercase px-1.5 py-0.5 rounded font-bold border border-outline-variant/30">
                    {node.type}
                  </span>
                </div>
              );
            })}
          </div>
        </aside>
      ) : (
        <div className="w-12 border-r border-outline-variant/30 bg-surface-container-lowest flex flex-col items-center py-4 select-none shrink-0">
          <button
            onClick={() => setIsExplorerExpanded(true)}
            className="text-on-surface-variant hover:text-on-surface cursor-pointer bg-transparent border-none"
            title="Expand Asset Explorer"
          >
            <span className="material-symbols-outlined text-[20px]">menu</span>
          </button>
        </div>
      )}

      {/* Center Canvas: Production Dynamic Topology Graph Render */}
      <div
        ref={containerRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
        onClick={() => setSelectedNodeId(null)}
        className={`flex-1 relative bg-[#06070A] overflow-hidden ${isDragging ? 'cursor-grabbing' : 'cursor-grab'}`}
      >
        <div
          className="absolute inset-0 opacity-20 pointer-events-none"
          style={{
            backgroundImage: 'radial-gradient(#1F242D 1px, transparent 1px)',
            backgroundSize: '32px 32px',
          }}
        />

        {loading ? (
          <div className="flex items-center justify-center h-full text-on-surface-variant font-mono">
            Generating Dynamic Security Risk Graph Topology...
          </div>
        ) : (
          <div
            className="absolute inset-0 z-10 origin-0 pointer-events-none"
            style={{
              transform: `translate(${panOffset.x}px, ${panOffset.y}px) scale(${zoomScale})`,
            }}
          >
            {/* Dynamic SVG Connection Edges */}
            <svg className="absolute inset-0 w-[4000px] h-[4000px] pointer-events-none z-0">
              {edges.map((edge) => {
                const srcNode = positionedNodes.find((n) => n.id === edge.source);
                const tgtNode = positionedNodes.find((n) => n.id === edge.target);
                if (!srcNode || !tgtNode) return null;

                const isHighlight = selectedNodeId === srcNode.id || selectedNodeId === tgtNode.id;
                const isCrit = edge.status === 'critical';
                const strokeColor = isHighlight
                  ? isCrit
                    ? '#ff4d4d'
                    : '#2E90FA'
                  : isCrit
                  ? '#8a1f1f'
                  : '#1F242D';

                const srcX = srcNode.posX + 200;
                const srcY = srcNode.posY + 20;
                const tgtX = tgtNode.posX;
                const tgtY = tgtNode.posY + 20;

                const pathD = `M ${srcX} ${srcY} C ${srcX + 120} ${srcY}, ${tgtX - 120} ${tgtY}, ${tgtX} ${tgtY}`;

                return (
                  <path
                    key={edge.id}
                    d={pathD}
                    fill="none"
                    stroke={strokeColor}
                    strokeWidth={isHighlight ? '2.5' : '1.5'}
                    strokeDasharray={isCrit ? '4' : undefined}
                  />
                );
              })}
            </svg>

            {/* Dynamic Node Elements */}
            {positionedNodes.map((node) => {
              const isSelected = selectedNodeId === node.id;
              const isCrit = node.status === 'critical';
              const isWarn = node.status === 'warning';

              return (
                <div
                  key={node.id}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNodeId(node.id);
                  }}
                  style={{ top: `${node.posY}px`, left: `${node.posX}px` }}
                  className="absolute flex flex-col items-center gap-1 group cursor-pointer z-10 select-none pointer-events-auto"
                >
                  <div
                    className={`px-3 py-1.5 rounded-lg border transition-all flex items-center gap-2 max-w-[240px] ${
                      isSelected
                        ? 'bg-primary-container/20 border-primary shadow-[0_0_15px_rgba(46,144,250,0.4)] scale-105'
                        : isCrit
                        ? 'bg-error/20 border-error/60 text-error'
                        : isWarn
                        ? 'bg-[#ff9800]/20 border-[#ff9800]/60 text-[#ff9800]'
                        : 'bg-surface-container-low border-outline-variant hover:border-primary/50'
                    }`}
                  >
                    <span
                      className={`material-symbols-outlined text-lg ${
                        isCrit ? 'text-error' : isWarn ? 'text-[#ff9800]' : 'text-primary'
                      }`}
                    >
                      {node.icon}
                    </span>
                    <span className="text-xs font-semibold text-on-surface truncate">{node.label}</span>
                  </div>
                  <span className="text-[9px] font-label-mono bg-[#0A0D12]/90 px-1.5 py-0.5 rounded border border-[#1F242D] text-on-surface-variant">
                    {node.type} • Score: {node.score}
                  </span>
                </div>
              );
            })}
          </div>
        )}

        {/* Canvas Controls */}
        <div className="absolute bottom-6 right-6 flex flex-col gap-2 z-30 select-none">
          <button
            onClick={handleZoomIn}
            className="w-10 h-10 rounded-full glass-panel flex items-center justify-center text-on-surface hover:text-primary transition-all cursor-pointer"
            title="Zoom In"
          >
            <span className="material-symbols-outlined">add</span>
          </button>
          <button
            onClick={handleZoomOut}
            className="w-10 h-10 rounded-full glass-panel flex items-center justify-center text-on-surface hover:text-primary transition-all cursor-pointer"
            title="Zoom Out"
          >
            <span className="material-symbols-outlined">remove</span>
          </button>
          <button
            onClick={handleFitToView}
            className="w-10 h-10 rounded-full glass-panel flex items-center justify-center text-on-surface hover:text-primary transition-all cursor-pointer"
            title="Fit to View"
          >
            <span className="material-symbols-outlined">fit_screen</span>
          </button>
        </div>
      </div>

      {/* Right Sidebar: Asset Node Inspector */}
      <aside className="w-96 border-l border-outline-variant/30 bg-surface-container-lowest flex flex-col z-10 shrink-0 relative glass-panel shadow-[-10px_0_30px_rgba(0,0,0,0.5)]">
        {selectedNode ? (
          <>
            <div className="p-4 border-b border-outline-variant/30 flex justify-between items-start select-none">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-label-mono font-bold border uppercase ${
                      selectedNode.status === 'critical'
                        ? 'bg-error/20 text-error border-error/30'
                        : 'bg-surface-container-high text-outline border-outline-variant/40'
                    }`}
                  >
                    {selectedNode.type}
                  </span>
                  <span className="text-xs text-outline font-label-mono">Asset Details</span>
                </div>
                <h2 className="font-label-mono text-on-surface text-sm break-all font-semibold select-all">
                  {selectedNode.label}
                </h2>
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedNodeId(null);
                }}
                className="text-outline hover:text-on-surface transition-colors cursor-pointer bg-transparent border-none"
              >
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>

            <div className="flex-grow overflow-y-auto p-4 space-y-6">
              <div
                className={`flex items-center gap-4 p-4 rounded-xl border ${
                  selectedNode.status === 'critical'
                    ? 'bg-error/10 border-error/20 text-error'
                    : selectedNode.status === 'warning'
                    ? 'bg-[#ff9800]/10 border-[#ff9800]/20 text-[#ff9800]'
                    : 'bg-[#10b981]/10 border-[#10b981]/20 text-[#10b981]'
                }`}
              >
                <div className="text-3xl font-bold">{selectedNode.score}</div>
                <div className="flex flex-col">
                  <span className="text-sm font-bold uppercase tracking-wider">
                    {selectedNode.status === 'critical'
                      ? 'Critical Risk'
                      : selectedNode.status === 'warning'
                      ? 'High/Medium Risk'
                      : 'Healthy Asset'}
                  </span>
                  <span className="text-xs text-on-surface-variant">
                    {selectedNode.verification_status ? `Status: ${selectedNode.verification_status}` : 'Evaluated'}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 select-all">
                <div className="p-3 rounded-lg bg-[#11151D] border border-[#1F242D]">
                  <div className="text-xs text-outline mb-1 font-label-mono">CWE</div>
                  <div className="text-sm text-on-surface font-semibold">{selectedNode.details?.cwe || 'N/A'}</div>
                </div>
                <div className="p-3 rounded-lg bg-[#11151D] border border-[#1F242D]">
                  <div className="text-xs text-outline mb-1 font-label-mono">OWASP</div>
                  <div className="text-sm text-on-surface font-semibold">{selectedNode.details?.owasp || 'N/A'}</div>
                </div>
                <div className="p-3 rounded-lg bg-[#11151D] border border-[#1F242D]">
                  <div className="text-xs text-outline mb-1 font-label-mono">Confidence</div>
                  <div className="text-sm text-on-surface font-semibold">
                    {selectedNode.confidence_score ? `${selectedNode.confidence_score}%` : 'N/A'}
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-[#11151D] border border-[#1F242D]">
                  <div className="text-xs text-outline mb-1 font-label-mono">Verification</div>
                  <div className="text-sm text-on-surface font-semibold">
                    {selectedNode.verification_status || 'N/A'}
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider">Asset Description</h3>
                <div className="p-3 rounded-lg border border-[#1F242D] bg-[#11151D]">
                  <p className="text-sm text-on-surface-variant leading-relaxed select-all">
                    {selectedNode.details?.description || 'No description available.'}
                  </p>
                  {selectedNode.details?.sastCode && (
                    <div className="bg-[#06070A] p-2 rounded border border-[#1F242D] font-mono text-xs text-outline overflow-x-auto whitespace-pre mt-2 select-all">
                      {selectedNode.details.sastCode}
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="p-4 border-t border-outline-variant/30 bg-surface-container-low flex gap-3 shrink-0">
              <button
                onClick={() => navigate('/findings')}
                className="flex-1 px-4 py-2 rounded-lg bg-surface-container-high border border-outline-variant text-on-surface text-sm font-semibold hover:bg-surface-bright transition-colors flex justify-center items-center gap-2 cursor-pointer"
              >
                View Vulnerabilities
              </button>
            </div>
          </>
        ) : (
          <div className="flex-grow flex flex-col items-center justify-center p-8 text-center text-on-surface-variant select-none">
            <span className="material-symbols-outlined text-4xl text-outline mb-3">hub</span>
            <h3 className="text-sm font-bold text-on-surface uppercase tracking-wider mb-2">Asset Inspector</h3>
            <p className="text-xs text-on-surface-variant leading-relaxed max-w-[220px]">
              Select any graph node on the canvas to inspect data flow relationships and finding evidence.
            </p>
          </div>
        )}
      </aside>
    </div>
  );
};

export default RiskMap;
