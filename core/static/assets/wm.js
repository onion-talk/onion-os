/* ==========================================================================
   OnionOS v1.0.0 — Multi-Window Desktop Compositor
   Simultaneous Floating Windows | 8-Dir Resize | 50/50 Edge Snap | Zero innerHTML
   ========================================================================== */

(() => {
  'use strict';

  const RESIZE_DIRS = ['n', 's', 'e', 'w', 'ne', 'nw', 'se', 'sw'];

  function setIframePointerShield(shielded) {
    document.querySelectorAll('.embed-iframe').forEach((frame) => {
      frame.style.pointerEvents = shielded ? 'none' : '';
    });
  }

  function createManager({ stageEl, snapPreviewEl, onStateChange, onWindowResize }) {
    const specs = new Map();
    const instances = new Map();
    let topZ = 100;
    let focusedId = '';

    function notifyChange() {
      if (typeof onStateChange === 'function') {
        onStateChange({
          focusedId,
          openWindows: getOpenWindows(),
        });
      }
    }

    function syncBackdropClasses() {
      for (const [id, inst] of instances.entries()) {
        const isVisible = inst.running && !inst.minimized;
        const isFocused = isVisible && id === focusedId;
        inst.el.classList.toggle('is-focused', isFocused);
        inst.el.classList.toggle('is-backdrop', isVisible && !isFocused);
      }
    }

    function pickNextTopWindow() {
      let bestId = '';
      let bestZ = -1;
      for (const [id, inst] of instances.entries()) {
        if (inst.running && !inst.minimized && inst.z > bestZ) {
          bestZ = inst.z;
          bestId = id;
        }
      }
      focusedId = bestId;
      syncBackdropClasses();
      notifyChange();
    }

    function updateMaximizeIcon(inst) {
      inst.maxBtn.replaceChildren(
        window.OnionIcons.createSymbolic(
          inst.el.classList.contains('is-maximized') ? 'restore' : 'maximize',
          13
        )
      );
    }

    function clearSnapStates(inst) {
      inst.el.classList.remove('is-maximized', 'is-tiled-left', 'is-tiled-right');
      updateMaximizeIcon(inst);
    }

    function buildWindowDom(spec) {
      const winEl = document.createElement('section');
      winEl.className = 'adw-window';
      winEl.dataset.appId = spec.id;
      winEl.setAttribute('aria-label', spec.title);

      const stageRect = stageEl.getBoundingClientRect();
      const stageW = Math.max(640, stageRect.width || window.innerWidth);
      const stageH = Math.max(460, stageRect.height || window.innerHeight - 34);

      const w = Math.min(spec.defaultWidth || 860, stageW - 28);
      const h = Math.min(spec.defaultHeight || 560, stageH - 86);
      const left = Math.max(14, Math.min(spec.defaultLeft ?? 64, stageW - w - 14));
      const top = Math.max(12, Math.min(spec.defaultTop ?? 26, stageH - h - 76));

      winEl.style.width = `${Math.round(w)}px`;
      winEl.style.height = `${Math.round(h)}px`;
      winEl.style.left = `${Math.round(left)}px`;
      winEl.style.top = `${Math.round(top)}px`;

      // HeaderBar
      const header = document.createElement('header');
      header.className = 'adw-headerbar';

      const startSlot = document.createElement('div');
      startSlot.className = 'headerbar-start';

      const centerSlot = document.createElement('div');
      centerSlot.className = 'headerbar-title-wrap';
      const titleIcon = window.OnionIcons.createAppIcon(spec.id, 20);
      const titleEl = document.createElement('h2');
      titleEl.className = 'headerbar-title';
      titleEl.textContent = spec.title;
      centerSlot.append(titleIcon, titleEl);

      const endWrap = document.createElement('div');
      endWrap.className = 'headerbar-end';
      const endSlot = document.createElement('div');
      endSlot.className = 'adw-row-group';

      const minBtn = document.createElement('button');
      minBtn.type = 'button';
      minBtn.className = 'win-ctrl-btn';
      minBtn.title = 'Minimize';
      minBtn.setAttribute('aria-label', `Minimize ${spec.title}`);
      minBtn.appendChild(window.OnionIcons.createSymbolic('minimize', 13));

      const maxBtn = document.createElement('button');
      maxBtn.type = 'button';
      maxBtn.className = 'win-ctrl-btn';
      maxBtn.title = 'Maximize';
      maxBtn.setAttribute('aria-label', `Maximize ${spec.title}`);
      maxBtn.appendChild(window.OnionIcons.createSymbolic('maximize', 13));

      const closeBtn = document.createElement('button');
      closeBtn.type = 'button';
      closeBtn.className = 'win-ctrl-btn is-close';
      closeBtn.title = 'Close';
      closeBtn.setAttribute('aria-label', `Close ${spec.title}`);
      closeBtn.appendChild(window.OnionIcons.createSymbolic('close', 13));

      endWrap.append(endSlot, minBtn, maxBtn, closeBtn);
      header.append(startSlot, centerSlot, endWrap);

      const contentEl = document.createElement('div');
      contentEl.className = 'adw-window-content';

      winEl.append(header, contentEl);

      const inst = {
        id: spec.id,
        spec,
        el: winEl,
        header,
        startSlot,
        centerSlot,
        titleEl,
        endSlot,
        maxBtn,
        contentEl,
        running: false,
        minimized: false,
        z: 100,
        savedRect: { left, top, width: w, height: h },
      };

      // Window Control Listeners
      minBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        minimize(spec.id);
      });
      maxBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleMaximize(spec.id);
      });
      closeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        close(spec.id);
      });

      header.addEventListener('dblclick', (e) => {
        if (e.target.closest('button, input, select')) return;
        toggleMaximize(spec.id);
      });

      winEl.addEventListener('pointerdown', () => {
        if (focusedId !== spec.id) {
          focus(spec.id);
        }
      });

      attachDragBehavior(inst);
      attachResizeHandles(inst);

      if (typeof spec.buildContent === 'function') {
        spec.buildContent({
          appId: spec.id,
          root: contentEl,
          startSlot,
          centerSlot,
          endSlot,
          setTitle(text) {
            titleEl.textContent = text;
          },
        });
      }

      stageEl.appendChild(winEl);
      instances.set(spec.id, inst);
      return inst;
    }

    function attachDragBehavior(inst) {
      let drag = null;

      inst.header.addEventListener('pointerdown', (e) => {
        if (e.button !== 0 || e.target.closest('button, input, select, textarea, a')) return;
        if (window.innerWidth <= 900) return;

        focus(inst.id);
        const sRect = stageEl.getBoundingClientRect();
        const wRect = inst.el.getBoundingClientRect();

        drag = {
          pointerId: e.pointerId,
          startX: e.clientX,
          startY: e.clientY,
          offsetX: e.clientX - wRect.left,
          offsetY: e.clientY - wRect.top,
          stageRect: sRect,
          snapCandidate: '',
          unsnapped: false,
        };

        setIframePointerShield(true);
        inst.header.setPointerCapture(e.pointerId);
      });

      inst.header.addEventListener('pointermove', (e) => {
        if (!drag || drag.pointerId !== e.pointerId) return;
        const dx = Math.abs(e.clientX - drag.startX);
        const dy = Math.abs(e.clientY - drag.startY);

        const isSnapped =
          inst.el.classList.contains('is-maximized') ||
          inst.el.classList.contains('is-tiled-left') ||
          inst.el.classList.contains('is-tiled-right');

        if (isSnapped && (dx > 6 || dy > 6) && !drag.unsnapped) {
          const prevW = inst.savedRect.width || 820;
          const prevH = inst.savedRect.height || 540;
          const ratio = Math.min(0.85, Math.max(0.15, (e.clientX - drag.stageRect.left) / drag.stageRect.width));
          clearSnapStates(inst);
          inst.el.style.width = `${Math.round(prevW)}px`;
          inst.el.style.height = `${Math.round(prevH)}px`;
          drag.offsetX = Math.round(prevW * ratio);
          drag.unsnapped = true;
        }

        if (isSnapped && !drag.unsnapped) return;

        const maxLeft = Math.max(0, drag.stageRect.width - 120);
        const maxTop = Math.max(0, drag.stageRect.height - 44);
        const nextLeft = Math.min(maxLeft, Math.max(-40, e.clientX - drag.stageRect.left - drag.offsetX));
        const nextTop = Math.min(maxTop, Math.max(0, e.clientY - drag.stageRect.top - drag.offsetY));

        inst.el.style.left = `${Math.round(nextLeft)}px`;
        inst.el.style.top = `${Math.round(nextTop)}px`;
        inst.savedRect.left = nextLeft;
        inst.savedRect.top = nextTop;

        // Edge Snap Detection (Left 50%, Right 50%, Top Maximize)
        const relX = e.clientX - drag.stageRect.left;
        const relY = e.clientY - drag.stageRect.top;
        if (relX <= 18) {
          drag.snapCandidate = 'left';
          showSnapPreview(6, 6, drag.stageRect.width / 2 - 10, drag.stageRect.height - 12);
        } else if (relX >= drag.stageRect.width - 18) {
          drag.snapCandidate = 'right';
          showSnapPreview(drag.stageRect.width / 2 + 4, 6, drag.stageRect.width / 2 - 10, drag.stageRect.height - 12);
        } else if (relY <= 8) {
          drag.snapCandidate = 'maximize';
          showSnapPreview(6, 6, drag.stageRect.width - 12, drag.stageRect.height - 12);
        } else {
          drag.snapCandidate = '';
          hideSnapPreview();
        }
      });

      const finishDrag = (e) => {
        if (!drag || drag.pointerId !== e.pointerId) return;
        setIframePointerShield(false);
        hideSnapPreview();

        if (drag.snapCandidate === 'left') {
          clearSnapStates(inst);
          inst.el.classList.add('is-tiled-left');
          if (typeof onWindowResize === 'function') onWindowResize(inst.id);
        } else if (drag.snapCandidate === 'right') {
          clearSnapStates(inst);
          inst.el.classList.add('is-tiled-right');
          if (typeof onWindowResize === 'function') onWindowResize(inst.id);
        } else if (drag.snapCandidate === 'maximize') {
          clearSnapStates(inst);
          inst.el.classList.add('is-maximized');
          updateMaximizeIcon(inst);
          if (typeof onWindowResize === 'function') onWindowResize(inst.id);
        }
        drag = null;
      };

      inst.header.addEventListener('pointerup', finishDrag);
      inst.header.addEventListener('pointercancel', finishDrag);
    }

    function attachResizeHandles(inst) {
      for (const dir of RESIZE_DIRS) {
        const handle = document.createElement('div');
        handle.className = `wm-resize wm-resize-${dir}`;
        inst.el.appendChild(handle);

        let rState = null;
        handle.addEventListener('pointerdown', (e) => {
          if (e.button !== 0 || window.innerWidth <= 900) return;
          if (
            inst.el.classList.contains('is-maximized') ||
            inst.el.classList.contains('is-tiled-left') ||
            inst.el.classList.contains('is-tiled-right')
          ) {
            return;
          }
          e.stopPropagation();
          focus(inst.id);
          const sRect = stageEl.getBoundingClientRect();
          const wRect = inst.el.getBoundingClientRect();
          rState = {
            pointerId: e.pointerId,
            startX: e.clientX,
            startY: e.clientY,
            origLeft: wRect.left - sRect.left,
            origTop: wRect.top - sRect.top,
            origW: wRect.width,
            origH: wRect.height,
            stageW: sRect.width,
            stageH: sRect.height,
          };
          setIframePointerShield(true);
          handle.setPointerCapture(e.pointerId);
        });

        handle.addEventListener('pointermove', (e) => {
          if (!rState || rState.pointerId !== e.pointerId) return;
          const dx = e.clientX - rState.startX;
          const dy = e.clientY - rState.startY;
          const minW = 380;
          const minH = 280;

          let nextL = rState.origLeft;
          let nextT = rState.origTop;
          let nextW = rState.origW;
          let nextH = rState.origH;

          if (dir.includes('e')) {
            nextW = Math.max(minW, Math.min(rState.stageW - nextL, rState.origW + dx));
          }
          if (dir.includes('s')) {
            nextH = Math.max(minH, Math.min(rState.stageH - nextT, rState.origH + dy));
          }
          if (dir.includes('w')) {
            const candidateW = Math.max(minW, rState.origW - dx);
            nextL = rState.origLeft + (rState.origW - candidateW);
            if (nextL < 0) {
              nextW = rState.origW + rState.origLeft;
              nextL = 0;
            } else {
              nextW = candidateW;
            }
          }
          if (dir.includes('n')) {
            const candidateH = Math.max(minH, rState.origH - dy);
            nextT = rState.origTop + (rState.origH - candidateH);
            if (nextT < 0) {
              nextH = rState.origH + rState.origTop;
              nextT = 0;
            } else {
              nextH = candidateH;
            }
          }

          inst.el.style.left = `${Math.round(nextL)}px`;
          inst.el.style.top = `${Math.round(nextT)}px`;
          inst.el.style.width = `${Math.round(nextW)}px`;
          inst.el.style.height = `${Math.round(nextH)}px`;
          inst.savedRect = { left: nextL, top: nextT, width: nextW, height: nextH };

          if (typeof onWindowResize === 'function') onWindowResize(inst.id);
        });

        const endResize = (e) => {
          if (rState && rState.pointerId === e.pointerId) {
            setIframePointerShield(false);
            rState = null;
          }
        };
        handle.addEventListener('pointerup', endResize);
        handle.addEventListener('pointercancel', endResize);
      }
    }

    function showSnapPreview(left, top, width, height) {
      if (!snapPreviewEl) return;
      snapPreviewEl.style.left = `${Math.round(left)}px`;
      snapPreviewEl.style.top = `${Math.round(top)}px`;
      snapPreviewEl.style.width = `${Math.round(width)}px`;
      snapPreviewEl.style.height = `${Math.round(height)}px`;
      snapPreviewEl.hidden = false;
    }

    function hideSnapPreview() {
      if (snapPreviewEl) snapPreviewEl.hidden = true;
    }

    function registerApp(spec) {
      specs.set(spec.id, spec);
    }

    function focus(appId) {
      const inst = instances.get(appId);
      if (!inst || !inst.running) return;
      inst.minimized = false;
      inst.el.hidden = false;
      topZ += 1;
      inst.z = topZ;
      inst.el.style.zIndex = String(topZ);
      focusedId = appId;
      syncBackdropClasses();
      if (typeof inst.spec.onFocus === 'function') {
        inst.spec.onFocus();
      }
      notifyChange();
    }

    function open(appId, payload) {
      const spec = specs.get(appId);
      if (!spec) return;
      let inst = instances.get(appId);
      if (!inst) {
        inst = buildWindowDom(spec);
      }
      const wasRunning = inst.running;
      inst.running = true;
      inst.minimized = false;
      inst.el.hidden = false;
      focus(appId);
      if (typeof spec.onOpen === 'function') {
        spec.onOpen(payload, !wasRunning);
      }
    }

    function minimize(appId) {
      const inst = instances.get(appId);
      if (!inst || !inst.running) return;
      inst.minimized = true;
      inst.el.hidden = true;
      pickNextTopWindow();
    }

    function toggleMaximize(appId) {
      const inst = instances.get(appId);
      if (!inst) return;
      const willMax = !inst.el.classList.contains('is-maximized');
      inst.el.classList.remove('is-tiled-left', 'is-tiled-right');
      inst.el.classList.toggle('is-maximized', willMax);
      updateMaximizeIcon(inst);
      focus(appId);
      if (typeof onWindowResize === 'function') onWindowResize(appId);
    }

    function close(appId) {
      const inst = instances.get(appId);
      if (!inst || !inst.running) return;
      inst.running = false;
      inst.minimized = false;
      inst.el.hidden = true;
      clearSnapStates(inst);
      if (typeof inst.spec.onClose === 'function') {
        inst.spec.onClose();
      }
      pickNextTopWindow();
    }

    function closeAll() {
      for (const id of instances.keys()) {
        const inst = instances.get(id);
        if (inst && inst.running) {
          inst.running = false;
          inst.minimized = false;
          inst.el.hidden = true;
          clearSnapStates(inst);
          if (typeof inst.spec.onClose === 'function') {
            inst.spec.onClose();
          }
        }
      }
      focusedId = '';
      syncBackdropClasses();
      notifyChange();
    }

    function toggleFromDock(appId) {
      const inst = instances.get(appId);
      if (!inst || !inst.running) {
        open(appId);
      } else if (inst.minimized) {
        focus(appId);
      } else if (focusedId === appId) {
        minimize(appId);
      } else {
        focus(appId);
      }
    }

    function getOpenWindows() {
      const list = [];
      for (const inst of instances.values()) {
        if (inst.running) {
          list.push({
            id: inst.id,
            title: inst.spec.title,
            minimized: inst.minimized,
            focused: inst.id === focusedId && !inst.minimized,
            z: inst.z,
          });
        }
      }
      list.sort((a, b) => b.z - a.z);
      return list;
    }

    return Object.freeze({
      registerApp,
      open,
      focus,
      minimize,
      toggleMaximize,
      close,
      closeAll,
      toggleFromDock,
      getOpenWindows,
      getFocusedAppId: () => focusedId,
    });
  }

  window.OnionWM = Object.freeze({ createManager });
})();
