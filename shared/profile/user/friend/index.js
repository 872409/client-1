// @flow
import * as React from 'react'
import * as Kb from '../../../common-adapters'
import * as Styles from '../../../styles'

type Props = {|
  followThem: boolean,
  followsYou: boolean,
  fullname: string,
  onClick: () => void,
  username: string,
  width: number,
|}

const Friend = (p: Props) => (
  <Kb.ClickableBox onClick={p.onClick} style={{width: p.width}}>
    <Kb.Box2
      direction="vertical"
      style={Styles.collapseStyles([styles.container, {width: p.width}])}
      centerChildren={true}
    >
      <Kb.Avatar size={64} username={p.username} style={styles.avatar} />
      <Kb.ConnectedUsernames type="Body" usernames={[p.username]} />
      <Kb.Text type="BodySmall" lineClamp={1}>
        {p.fullname}
      </Kb.Text>
    </Kb.Box2>
  </Kb.ClickableBox>
)

const styles = Styles.styleSheetCreate({
  avatar: {
    marginBottom: Styles.globalMargins.xxtiny,
  },
  container: {
    flexShrink: 0,
    height: 105,
    justifyContent: 'flex-start',
    minWidth: 0,
  },
})

export default Friend