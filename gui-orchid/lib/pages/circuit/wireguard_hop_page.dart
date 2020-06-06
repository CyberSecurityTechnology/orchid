import 'package:flutter/material.dart';
import 'package:orchid/generated/l10n.dart';
import 'package:orchid/pages/common/config_text.dart';
import 'package:orchid/pages/common/formatting.dart';
import 'package:orchid/pages/common/instructions_view.dart';
import 'package:orchid/pages/common/screen_orientation.dart';
import 'package:orchid/pages/common/tap_clears_focus.dart';
import 'package:orchid/pages/common/titled_page_base.dart';
import '../app_sizes.dart';
import 'hop_editor.dart';
import 'model/wireguard_hop.dart';

/// Create / edit / view an WireGuard Hop
class WireGuardHopPage extends HopEditor<WireGuardHop> {
  WireGuardHopPage(
      {@required editableHop, mode = HopEditorMode.View, onAddFlowComplete})
      : super(
            editableHop: editableHop,
            mode: mode,
            onAddFlowComplete: onAddFlowComplete);

  @override
  _WireGuardHopPageState createState() => _WireGuardHopPageState();
}

class _WireGuardHopPageState extends State<WireGuardHopPage> {
  var _config = TextEditingController();

  @override
  void initState() {
    super.initState();

    // Disable rotation until we update the screen design
    ScreenOrientation.portrait();

    WireGuardHop hop = widget.editableHop.value?.hop;
    setState(() {
      _config.text = hop?.config;
    }); // Setstate to update the hop for any defaulted values.
    _config.addListener(_updateHop);
  }

  @override
  void setState(VoidCallback fn) {
    super.setState(fn);
    _updateHop();
  }

  @override
  Widget build(BuildContext context) {
    double screenHeight = MediaQuery.of(context).size.height;
    return TapClearsFocus(
      child: TitledPage(
        title: "WireGuard Hop",
        decoration: BoxDecoration(),
        actions: widget.mode == HopEditorMode.Create
            ? [widget.buildSaveButton(context, widget.onAddFlowComplete)]
            : [],
        child: SafeArea(
          child: SingleChildScrollView(
            child: Padding(
              padding: const EdgeInsets.all(24.0),
              child: Center(
                child: ConstrainedBox(
                  constraints: BoxConstraints(maxWidth: 700),
                  child: Column(
                    children: <Widget>[
                      if (AppSize(context).tallerThan(AppSize.iphone_xs_max))
                        pady(64),
                      pady(16),
                      ConfigLabel(text: s.config),
                      ConfigText(
                        height: screenHeight / 2.8,
                        textController: _config,
                        hintText: "Paste your WireGuard config file here",
                      ),

                      // Instructions
                      Visibility(
                        visible: widget.mode == HopEditorMode.Create,
                        child: InstructionsView(
                          title: s.enterYourCredentials,
                          body:
                              "Paste the credential information for your WireGuard provider into the field above.",
                        ),
                      ),
                      pady(24)
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  void _updateHop() {
    if (!widget.editable()) {
      return;
    }
    widget.editableHop.update(WireGuardHop(config: _config.text));
  }

  @override
  void dispose() {
    super.dispose();
    ScreenOrientation.reset();
    _config.removeListener(_updateHop);
  }

  S get s {
    return S.of(context);
  }
}